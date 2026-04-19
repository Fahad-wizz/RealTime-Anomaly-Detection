import random
import os
import secrets
import signal
import sqlite3
import threading
import time
import uuid
from functools import wraps
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from flask import Flask, redirect, render_template, request, send_file, session, url_for
from flask_socketio import SocketIO
from werkzeug.security import check_password_hash, generate_password_hash
from flask import jsonify

import flow_features
import metrics
from model import FEATURE_COLUMNS, preprocess as preprocess_training_frame
from sniffer import packet_queue, start_sniffing

AGENT_URL = None
LAST_AGENT_TIME = 0
AGENT_TIMEOUT = 5  # seconds
LIVE_DATA = []
MAX_BUFFER = 100

RAW_PACKET_COLUMNS = {"time", "source", "destination", "protocol", "length"}
MODEL_FEATURE_COLUMNS = FEATURE_COLUMNS

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / "uploads"
PRIMARY_DB_PATH = BASE_DIR / "database.db"
FALLBACK_DB_PATH = BASE_DIR / "database_runtime.db"
MEMORY_DB_URI = "file:ids_runtime?mode=memory&cache=shared"
ACTIVE_DB_PATH = PRIMARY_DB_PATH
ACTIVE_DB_USE_URI = False
DB_KEEPALIVE = None
MODELS_DIR = BASE_DIR / "models"

UPLOAD_FOLDER.mkdir(exist_ok=True)

active_clients = 0
active_clients_lock = threading.Lock()
ENABLE_SNIFFER = False
stop_threads = False

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

socketio = SocketIO(app, async_mode='threading')

isolation_model = joblib.load(MODELS_DIR / "model.pkl")
isolation_scaler = joblib.load(MODELS_DIR / "scaler.pkl")
classifier = joblib.load(MODELS_DIR / "classifier.pkl")
classifier_scaler = joblib.load(MODELS_DIR / "classifier_scaler.pkl")


def get_db_connection():
    conn = sqlite3.connect(ACTIVE_DB_PATH, uri=ACTIVE_DB_USE_URI)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_schema(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src TEXT,
            dst TEXT,
            proto TEXT,
            attack_type TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS db_healthcheck (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            touched_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute("INSERT INTO db_healthcheck DEFAULT VALUES")
    conn.execute(
        "DELETE FROM db_healthcheck WHERE id = (SELECT MAX(id) FROM db_healthcheck)"
    )
    conn.commit()


def init_db():
    global ACTIVE_DB_PATH, ACTIVE_DB_USE_URI, DB_KEEPALIVE

    last_error = None
    for candidate, use_uri in (
        (PRIMARY_DB_PATH, False),
        (FALLBACK_DB_PATH, False),
        (MEMORY_DB_URI, True),
    ):
        try:
            ACTIVE_DB_PATH = candidate
            ACTIVE_DB_USE_URI = use_uri

            if use_uri:
                DB_KEEPALIVE = get_db_connection()
                initialize_schema(DB_KEEPALIVE)
            else:
                with get_db_connection() as conn:
                    initialize_schema(conn)
            return
        except sqlite3.OperationalError as exc:
            last_error = exc
            if DB_KEEPALIVE is not None:
                DB_KEEPALIVE.close()
                DB_KEEPALIVE = None

    raise last_error


init_db()


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("home"))
        return view_func(*args, **kwargs)

    return wrapped_view


def is_hashed_password(value):
    return isinstance(value, str) and value.startswith(("pbkdf2:", "scrypt:"))


def verify_password(stored_password, provided_password):
    if is_hashed_password(stored_password):
        return check_password_hash(stored_password, provided_password)
    return stored_password == provided_password


def result_path_for(file_id):
    try:
        normalized = str(uuid.UUID(str(file_id)))
    except ValueError:
        return None
    return UPLOAD_FOLDER / f"result_{normalized}.csv"


def log_attack(data, attack_type):
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO attacks (src, dst, proto, attack_type)
            VALUES (?, ?, ?, ?)
            """,
            (
                data.get("src"),
                data.get("dst"),
                str(data.get("proto", "Unknown")),
                attack_type,
            ),
        )


def latest_result_summary():
    file_id = session.get("last_result_file_id")
    if not file_id:
        return None

    result_path = result_path_for(file_id)
    if result_path is None or not result_path.exists():
        return None

    df = pd.read_csv(result_path)
    attacks = int((df["prediction"] == "ATTACK").sum())
    total = int(len(df))
    return {
        "total": total,
        "anomalies": attacks,
        "normal": total - attacks,
    }


def build_flow_features_from_packets(df):
    df = df.copy()
    df.columns = df.columns.str.strip().str.lower()

    grouped = (
        df.groupby("flow_id")
        .agg(
            src=("source", "first"),
            dst=("destination", "first"),
            proto=("protocol", "first"),
            packet_count=("length", "count"),
            byte_count=("length", "sum"),
            start_time=("time", "min"),
            end_time=("time", "max"),
        )
        .reset_index()
    )

    duration = (grouped["end_time"] - grouped["start_time"]).dt.total_seconds()
    duration = duration.clip(lower=0.001).fillna(0.001)

    grouped["duration"] = duration
    grouped["packet_rate"] = grouped["packet_count"] / grouped["duration"]
    grouped["byte_rate"] = grouped["byte_count"] / grouped["duration"]

    return grouped[["flow_id", "src", "dst", "proto", *MODEL_FEATURE_COLUMNS]]


def map_cicids_to_model_features(df):

    df = df.copy()

    # 🔥 NORMALIZE COLUMNS
    df.columns = df.columns.str.strip().str.lower()

    # 🔥 ROBUST RENAME (handles BOTH cases)
    rename_map = {
        # FEATURES
        "total fwd packets": "packet_count",
        "total length of fwd packets": "byte_count",
        "flow duration": "duration",
        "flow packets/s": "packet_rate",
        "flow bytes/s": "byte_rate",

        # 🔥 METADATA (FIXED HERE)
        "source ip": "src",
        "source": "src",

        "destination ip": "dst",
        "destination": "dst",

        "protocol": "proto",
    }

    df = df.rename(columns=rename_map)

    # 🔥 DEBUG (IMPORTANT — KEEP TEMPORARILY)
    print("COLUMNS AFTER RENAME:", df.columns.tolist())

    out = pd.DataFrame(index=df.index)

    # 🔥 SAFE METADATA EXTRACTION
    out["src"] = df["src"] if "src" in df.columns else "N/A"
    out["dst"] = df["dst"] if "dst" in df.columns else "N/A"
    out["proto"] = df["proto"] if "proto" in df.columns else "Unknown"

    # 🔥 FORCE CLEAN VALUES (CRITICAL)
    out["src"] = out["src"].astype(str)
    out["dst"] = out["dst"].astype(str)
    out["proto"] = out["proto"].astype(str)

    out["src"] = out["src"].replace(["nan", "None", "", "NaN"], "N/A")
    out["dst"] = out["dst"].replace(["nan", "None", "", "NaN"], "N/A")
    out["proto"] = out["proto"].replace(["nan", "None", "", "NaN"], "Unknown")

    # 🔥 FINAL DEBUG (THIS WILL PROVE FIX)
    print("SRC SAMPLE:", out["src"].head(10))

    # 🔥 FEATURES
    for col in MODEL_FEATURE_COLUMNS:
        if col in df.columns:
            out[col] = pd.to_numeric(df[col], errors="coerce")
        else:
            out[col] = 0

    # 🔥 CLEAN NUMERICS
    out.replace([np.inf, -np.inf], np.nan, inplace=True)
    out.fillna(0, inplace=True)

    if "duration" in out.columns:
        out["duration"] = out["duration"].clip(lower=0.001)

    return out[["src", "dst", "proto", *MODEL_FEATURE_COLUMNS]]



def normalize_flow_dataframe(df):
    flow_df = preprocess_training_frame(df.copy())

    if flow_df.empty:
        raise ValueError("Empty after preprocessing")

    # 🔥 FORCE METADATA EXTRACTION FROM ORIGINAL DF
    df.columns = df.columns.str.strip().str.lower()

    flow_df["src"] = df.get("source ip", df.get("source", "N/A"))
    flow_df["dst"] = df.get("destination ip", df.get("destination", "N/A"))
    flow_df["proto"] = df.get("protocol", "Unknown")

    # 🔥 CLEAN
    flow_df["src"] = flow_df["src"].astype(str).replace(["nan", "None"], "N/A")
    flow_df["dst"] = flow_df["dst"].astype(str).replace(["nan", "None"], "N/A")
    flow_df["proto"] = flow_df["proto"].astype(str).replace(["nan", "None"], "Unknown")

    # 🔥 FINAL COLUMN ORDER
    required_cols = ["src", "dst", "proto", *MODEL_FEATURE_COLUMNS]

    return flow_df[required_cols]


def prepare_upload_features(df):
    normalized = df.copy()
    normalized.columns = normalized.columns.str.strip().str.lower()

    normalized = normalized.rename(columns={
        "source ip": "source",
        "destination ip": "destination",
        "flow id": "flow_id",
        "flow duration": "duration",
        "flow bytes/s": "byte_rate",
        "flow packets/s": "packet_rate",
        "total fwd packets": "packet_count",
        "total length of fwd packets": "byte_count",
    })

    # Raw packet mode
    if RAW_PACKET_COLUMNS.issubset(set(normalized.columns)):
        packet_df = normalized.copy()
        packet_df["length"] = pd.to_numeric(packet_df["length"], errors="coerce")

        numeric_time = pd.to_numeric(packet_df["time"], errors="coerce")
        if numeric_time.notna().sum() >= max(1, int(len(packet_df) * 0.8)):
            packet_df["time"] = pd.to_datetime(
                numeric_time, unit="s", origin="unix", errors="coerce"
            )
        else:
            packet_df["time"] = pd.to_datetime(packet_df["time"], errors="coerce")

        packet_df = packet_df.dropna(subset=["time", "length"])
        if packet_df.empty:
            raise ValueError("The uploaded packet capture does not contain any valid rows.")

        packet_df["flow_id"] = (
            packet_df["source"].astype(str)
            + "_"
            + packet_df["destination"].astype(str)
            + "_"
            + packet_df["protocol"].astype(str)
        )
        return build_flow_features_from_packets(packet_df)

    # CICIDS flow mode
    flow_df = map_cicids_to_model_features(normalized)

    if flow_df.empty:
        raise ValueError("The uploaded flow data is empty after preprocessing.")

    return flow_df


def score_flows(feature_df):
    results = feature_df.reset_index(drop=True).copy()

    if results.empty:
        raise ValueError("The uploaded data did not produce any flows to score.")

    model_input = results[MODEL_FEATURE_COLUMNS].copy()
    model_input = model_input.replace([np.inf, -np.inf], 0).fillna(0)
    model_input = model_input.clip(lower=0, upper=1e6)

    anomaly_scaled = isolation_scaler.transform(model_input)
    anomaly_flags = isolation_model.predict(anomaly_scaled)
    anomaly_scores = isolation_model.decision_function(anomaly_scaled)

    min_s, max_s = anomaly_scores.min(), anomaly_scores.max()
    anomaly_conf = ((anomaly_scores - min_s) / (max_s - min_s + 1e-8)) * 100

    classifier_scaled = classifier_scaler.transform(model_input)
    classifier_labels = list(classifier.predict(classifier_scaled))

    if hasattr(classifier, "predict_proba"):
        probabilities = classifier.predict_proba(classifier_scaled)
        classifier_confidences = [float(max(row) * 100) for row in probabilities]
    else:
        classifier_confidences = [50.0] * len(results)

    scored_rows = []
    for idx, row in results.iterrows():
        anomaly_flag = int(anomaly_flags[idx])
        classifier_label = str(classifier_labels[idx])
        clf_conf = classifier_confidences[idx]
        anom_conf = anomaly_conf[idx]

        if classifier_label != "Normal":
            prediction = "ATTACK"
            attack_type = classifier_label
            confidence = round(clf_conf * 0.95, 2)
        elif anomaly_flag == -1:
            prediction = "ATTACK"
            attack_type = "Anomaly"
            confidence = round(float(anom_conf), 2)
        else:
            prediction = "NORMAL"
            attack_type = "Normal"
            confidence = round(clf_conf * 0.95, 2)

        scored_rows.append({
            "flow_id": row.get("flow_id", f"flow_{idx}"),
            "src": row.get("src", "N/A") if pd.notna(row.get("src", "N/A")) else "N/A",
            "dst": row.get("dst", "N/A") if pd.notna(row.get("dst", "N/A")) else "N/A",
            "proto": row.get("proto", "Unknown") if pd.notna(row.get("proto", "Unknown")) else "Unknown",
            "prediction": prediction,
            "attack_type": attack_type,
            "confidence": round(float(confidence), 2),
            "duration": round(float(row.get("duration", 0) or 0), 6),
            "bytes": round(float(row.get("byte_count", 0) or 0), 2),
            "anomaly_flag": anomaly_flag,
        })

    return pd.DataFrame(scored_rows)


def classify_live_flow(feature_row):
    feature_df = pd.DataFrame([feature_row])

    # 🔥 ALIGNMENT FIX
    feature_df = feature_df.reindex(columns=MODEL_FEATURE_COLUMNS, fill_value=0)

    model_input = feature_df.reindex(columns=MODEL_FEATURE_COLUMNS, fill_value=0)
    model_input = model_input.clip(lower=0, upper=1e5)

    anomaly_scaled = isolation_scaler.transform(model_input)
    anomaly_flag = int(isolation_model.predict(anomaly_scaled)[0])

    classifier_scaled = classifier_scaler.transform(model_input)
    classifier_label = str(classifier.predict(classifier_scaled)[0])

    confidence = 100.0
    if hasattr(classifier, "predict_proba"):
        confidence = float(max(classifier.predict_proba(classifier_scaled)[0]) * 100)

    # 🔥 FIXED DECISION LOGIC
    if classifier_label != "Normal" and confidence > 60:
        return -1, classifier_label, round(confidence, 2)

    if anomaly_flag == -1:
        return -1, "Anomaly", 80.0

    return 1, "Normal", round(confidence, 2)

@app.route("/api/ingest", methods=["POST"])
def ingest_live_data():
    global LIVE_DATA, LAST_AGENT_TIME

    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No data received"}), 400

        # ✅ normalize input
        rows = data if isinstance(data, list) else [data]

        processed = 0

        for row in rows:
            # 🔥 sanitize metadata (VERY IMPORTANT)
            src = str(row.get("src", "N/A"))
            dst = str(row.get("dst", "N/A"))
            proto = str(row.get("proto", "Unknown"))

            # 🔥 build feature input
            feature_input = {k: row.get(k, 0) for k in MODEL_FEATURE_COLUMNS}

            pred, attack_type, confidence = classify_live_flow(feature_input)

            # ✅ update metrics
            metrics.update_metrics(
                {"src": src, "dst": dst, "proto": proto},
                pred,
                attack_type
            )

            # ✅ log attacks
            if pred == -1:
                log_attack(row, attack_type)

            # ✅ store result
            LIVE_DATA.append({
                "src": src,
                "dst": dst,
                "proto": proto,
                "attack_type": attack_type,
                "confidence": float(confidence),
                "anomaly": int(pred),
                "timestamp": time.time()
            })

            processed += 1

        # 🔥 update heartbeat AFTER success
        LAST_AGENT_TIME = time.time()

        # ✅ prevent memory overflow
        if len(LIVE_DATA) > MAX_BUFFER:
            LIVE_DATA = LIVE_DATA[-MAX_BUFFER:]

        return jsonify({
            "status": "ok",
            "processed": processed
        })

    except Exception as e:
        print("API ERROR:", e)
        return jsonify({"error": str(e)}), 500
    
@app.route("/agent/register", methods=["POST"])
def register_agent():
    global AGENT_URL

    data = request.json
    AGENT_URL = data.get("url")

    print("🔥 Agent registered:", AGENT_URL)

    return jsonify({"status": "registered"})

@app.route("/api/live")
def get_live_data():
    now = time.time()
    agent_active = (now - LAST_AGENT_TIME) < AGENT_TIMEOUT

    # 🔥 AUTO DEMO MODE
    if not agent_active:

        fake = {
            "src": f"192.168.1.{random.randint(1,255)}",
            "dst": "8.8.8.8",
            "proto": "TCP",
            "attack_type": random.choice(["Normal", "DoS", "PortScan"]),
            "confidence": random.randint(60, 100),
            "anomaly": random.choice([1, -1]),
            "timestamp": time.time()
        }

        LIVE_DATA.append(fake)

         # 🔥 ADD THIS (CRITICAL)
        metrics.update_metrics(
        {
            "src": fake["src"],
            "dst": fake["dst"],
            "proto": fake["proto"]
        },
        fake["anomaly"],
        fake["attack_type"]
        )

        if len(LIVE_DATA) > MAX_BUFFER:
            LIVE_DATA.pop(0)

    return jsonify({
        "data": LIVE_DATA,
        "metrics": metrics.get_metrics(),
        "agent_active": agent_active
    })

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db_connection() as conn:
            row = conn.execute(
                "SELECT id, username, password FROM users WHERE username=?",
                (user,),
            ).fetchone()

            if row and verify_password(row["password"], password):
                if not is_hashed_password(row["password"]):
                    conn.execute(
                        "UPDATE users SET password=? WHERE id=?",
                        (generate_password_hash(password), row["id"]),
                    )
                session["user"] = row["username"]
                return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid username or password.")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not user or not password:
            return render_template("register.html", error="Username and password are required.")

        with get_db_connection() as conn:
            existing = conn.execute(
                "SELECT 1 FROM users WHERE username=?",
                (user,),
            ).fetchone()
            if existing:
                return render_template("register.html", error="User already exists.")

            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (user, generate_password_hash(password)),
            )

        session["user"] = user
        return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/dashboard")
@login_required
def dashboard():
    with get_db_connection() as conn:
        alerts = conn.execute(
            """
            SELECT src, proto, attack_type, timestamp
            FROM attacks
            ORDER BY id DESC
            LIMIT 10
            """
        ).fetchall()

    return render_template(
        "dashboard.html",
        data=latest_result_summary(),
        initial_metrics=metrics.get_metrics(),
        recent_alerts=alerts,
    )


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        file = request.files.get("file")

        # -------------------------------
        # VALIDATION
        # -------------------------------
        if not file or not file.filename:
            return "No file", 400

        if not file.filename.lower().endswith(".csv"):
            return "Only CSV uploads are supported.", 400

        try:
            # -------------------------------
            # STEP 1: LOAD CSV
            # -------------------------------
            uploaded_df = pd.read_csv(file)

            print("\n📥 RAW CSV COLUMNS:", uploaded_df.columns.tolist())
            print("📥 RAW SAMPLE:\n", uploaded_df.head(3))

            # -------------------------------
            # STEP 2: NORMALIZATION (SAFE)
            # -------------------------------
            # 🔥 FORCE SAME PIPELINE AS LOCAL (CRITICAL)
            feature_df = prepare_upload_features(uploaded_df)
            print("✅ Using prepare_upload_features (production stable)")


            # -------------------------------
            # STEP 3: STRICT FEATURE CHECK
            # -------------------------------
            missing = [
                col for col in MODEL_FEATURE_COLUMNS
                if col not in feature_df.columns
            ]

            if missing:
                raise ValueError(f"❌ Missing required features: {missing}")
            
            if not all(col in feature_df.columns for col in ["src", "dst", "proto"]):
                raise ValueError("Missing metadata → fallback required")

            # -------------------------------
            # STEP 4: ZERO / NAN DETECTION
            # -------------------------------
            zero_ratio = (feature_df[MODEL_FEATURE_COLUMNS] == 0).mean().mean()
            nan_ratio = feature_df[MODEL_FEATURE_COLUMNS].isna().mean().mean()

            print(f"📊 ZERO RATIO: {zero_ratio:.2f}")
            print(f"📊 NAN RATIO: {nan_ratio:.2f}")

            if zero_ratio > 0.8:
                raise ValueError("❌ Features are mostly ZERO → wrong mapping")

            if nan_ratio > 0.3:
                raise ValueError("❌ Too many NaN values → bad preprocessing")

            print("📊 FINAL FEATURES SAMPLE:\n", feature_df.head(5))

            # -------------------------------
            # STEP 5: MODEL SCORING
            # -------------------------------
            results_df = score_flows(feature_df)

        except ValueError as exc:
            return f"DATA ERROR: {exc}", 400

        except Exception as exc:
            return f"SYSTEM ERROR: {exc}", 500

        # -------------------------------
        # STEP 6: SAVE RESULTS
        # -------------------------------
        file_id = str(uuid.uuid4())
        output_path = result_path_for(file_id)

        results_df.to_csv(output_path, index=False)
        session["last_result_file_id"] = file_id

        return redirect(url_for("upload_results", file_id=file_id))

    # GET request
    return render_template("upload.html")



@app.route("/upload/results/<file_id>")
@login_required
def upload_results(file_id):
    import math

    result_path = result_path_for(file_id)
    if result_path is None or not result_path.exists():
        return "Result file not found.", 404

    df = pd.read_csv(result_path)

    # -------- SUMMARY -------- #
    avg_conf = round(df["confidence"].mean(), 2) if not df.empty else 0
    summary = {
        "total": len(df),
        "attacks": len(df[df["prediction"] == "ATTACK"]),
        "normal": len(df[df["prediction"] == "NORMAL"]),
        "avg_conf": avg_conf,
    }

    # -------- CHART DATA -------- #
    attack_counts = df["attack_type"].value_counts().to_dict()

    # -------- PAGINATION -------- #
    page = int(request.args.get("page", 1))
    per_page = 100   # 🔥 IMPORTANT (DO NOT INCREASE)

    start = (page - 1) * per_page
    end = start + per_page

    page_df = df.iloc[start:end]

    total_pages = max(1, math.ceil(len(df) / per_page))

    return render_template(
        "result.html", 
        data=page_df.to_dict(orient="records"),
        summary=summary,
        attack_counts=attack_counts,
        page=page,
        total_pages=total_pages,
        file_id=file_id
    )


@app.route("/download/<file_id>")
@login_required
def download_result(file_id):
    result_path = result_path_for(file_id)
    if result_path is None or not result_path.exists():
        return "Result file not found.", 404
    return send_file(result_path, as_attachment=True, download_name=result_path.name)

@app.route("/monitor")
@login_required
def monitor():
    return render_template("monitor.html")

import requests

def get_agent_url():
    if not AGENT_URL:
        raise Exception("Agent not connected")
    return AGENT_URL

@app.route("/attack/start", methods=["POST"])
def start_attack():
    url = get_agent_url()
    res = requests.post(f"{url}/attack/start", json=request.json)
    return res.json()


@app.route("/attack/status/<attack_id>")
def attack_status(attack_id):
    url = get_agent_url()
    res = requests.get(f"{url}/attack/status/{attack_id}")
    return res.json()


@app.route("/attack/stop", methods=["POST"])
def stop_attack():
    url = get_agent_url()
    res = requests.post(f"{url}/attack/stop", json=request.json)
    return res.json()

@app.route("/agent/status")
def agent_status():
    return jsonify({
        "connected": AGENT_URL is not None
    })

@app.route("/api/live-data")
def live_data():

    since = request.args.get("since", type=float)

    if since:
        filtered = [x for x in LIVE_DATA if x["timestamp"] > since]
    else:
        filtered = LIVE_DATA[-50:]

    # 🔥 NORMALIZE FORMAT FOR FRONTEND
    output = []

    for item in filtered:
        output.append({
            "timestamp": item["timestamp"],
            "src": item["src"],
            "prediction": "ATTACK" if item["anomaly"] == -1 else "NORMAL",
            "attack_type": item["attack_type"],
            "confidence": item["confidence"]
        })

    return jsonify(output)

def background_sniffer():
    print("Sniffer started")
    start_sniffing()


def send_live_data():
    while not stop_threads:
        if packet_queue.empty():
            time.sleep(0.2)
            continue

        data = packet_queue.get()
        key, flow = flow_features.update_flow(data)

        if not flow_features.is_flow_ready(flow):
            continue

        feature_row = flow_features.extract_features(flow)

        try:
            pred, attack_type, confidence = classify_live_flow(feature_row)
        except Exception as exc:
            print("ML Error:", exc)
            pred, attack_type, confidence = -1, "Unknown", 0.0

        metrics.update_metrics(data, pred, attack_type)
        if pred == -1:
            log_attack(data, attack_type)

        socketio.emit(
            "packet",
            {
                "src": data.get("src"),
                "dst": data.get("dst"),
                "proto": data.get("proto"),
                "anomaly": pred,
                "attack_type": attack_type,
                "confidence": confidence,
                "metrics": metrics.get_metrics(),
            },
        )

        print(
            f"FLOW DETECTED -> {attack_type} | "
            f"packets={feature_row['packet_count']} | anomaly={pred}"
        )

        flow_features.flows.pop(key, None)


def shutdown_handler(sig, frame):
    global stop_threads
    print("Shutting down cleanly...")
    stop_threads = True
    raise SystemExit(0)


signal.signal(signal.SIGINT, shutdown_handler)


@socketio.on("connect")
def handle_connect():
    global active_clients
    with active_clients_lock:
        active_clients += 1
        count = active_clients
    print("Client connected:", count)


@socketio.on("disconnect")
def handle_disconnect():
    global active_clients
    with active_clients_lock:
        active_clients = max(0, active_clients - 1)
        count = active_clients
    print("Client disconnected:", count)


if __name__ == "__main__":
    if ENABLE_SNIFFER:
        threading.Thread(target=background_sniffer, daemon=True).start()
        threading.Thread(target=send_live_data, daemon=True).start()

    socketio.run(app,host="0.0.0.0", port=10000, debug=True)
