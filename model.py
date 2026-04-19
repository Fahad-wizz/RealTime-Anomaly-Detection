from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# ---------------- PATHS ---------------- #

DATASET_PATH = Path("dataset") / "attack_data.csv"
MODEL_PATH = Path("models") / "model.pkl"
SCALER_PATH = Path("models") / "scaler.pkl"
RESULTS_PATH = Path("dataResults") / "anomaly_results.csv"


# ---------------- FEATURES ---------------- #

FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "duration",
    "packet_rate",
    "byte_rate",
]


# ---------------- LABEL SIMPLIFICATION ---------------- #

def simplify_label(label):
    label = str(label).strip()

    if label.upper() == "BENIGN":
        return "Normal"
    if "DoS" in label or "DDoS" in label:
        return "DDoS"
    if "Brute" in label or "Patator" in label:
        return "BruteForce"
    if "Scan" in label:
        return "Scan"

    return label if label else "Unknown"


# ---------------- LOAD DATA ---------------- #

def load_data(file_path=DATASET_PATH):
    print("📂 Loading dataset...")
    df = pd.read_csv(file_path)
    df.columns = df.columns.str.strip()
    print("✔ Loaded:", df.shape)
    return df


# ---------------- PREPROCESS ---------------- #

def preprocess(df):
    print("⚙️ Preprocessing...")

    df = df.copy()
    df.columns = df.columns.str.strip()

    rename_map = {
        "Total Fwd Packets": "packet_count",
        "Total Length of Fwd Packets": "byte_count",
        "Flow Duration": "duration",
        "Flow Packets/s": "packet_rate",
        "Flow Bytes/s": "byte_rate",
        "Label": "label",
    }

    df = df.rename(columns=rename_map)

    # Ensure required columns exist
    missing = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    df = df[FEATURE_COLUMNS + ["label"]]

    # Convert numeric
    for col in FEATURE_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Clean NaN / inf
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(subset=FEATURE_COLUMNS, inplace=True)

    # Convert duration (microseconds → seconds)
    df["duration"] = df["duration"] / 1e6
    df["duration"] = df["duration"].clip(lower=0.001)

    # Clip extreme values (VERY IMPORTANT)
    df["packet_rate"] = df["packet_rate"].clip(upper=1e6)
    df["byte_rate"] = df["byte_rate"].clip(upper=1e8)

    # Normalize labels
    df["label"] = df["label"].apply(simplify_label)

    print("✔ After preprocess:", df.shape)
    print("📊 Label distribution:\n", df["label"].value_counts())

    return df.reset_index(drop=True)


# ---------------- TRAIN DATA PREP ---------------- #

def get_training_frame(file_path=DATASET_PATH, benign_only=True):
    df = preprocess(load_data(file_path))

    if benign_only:
        df = df[df["label"] == "Normal"]

        print("✔ After filtering Normal:", df.shape)

        if df.empty:
            raise ValueError(
                "❌ Training data is EMPTY after filtering.\n"
                "Check label preprocessing or dataset."
            )

    return df


# ---------------- TRAIN MODEL ---------------- #

def train_isolation_forest(df):
    print("🚀 Training Isolation Forest...")

    scaler = StandardScaler()
    X = scaler.fit_transform(df[FEATURE_COLUMNS])

    model = IsolationForest(
        n_estimators=150,   # slightly reduced for speed
        contamination=0.02,
        random_state=42,
    )

    model.fit(X)

    MODEL_PATH.parent.mkdir(exist_ok=True)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    print("✅ Model saved at:", MODEL_PATH)
    print("✅ Scaler saved at:", SCALER_PATH)

    return model, scaler


# ---------------- DETECT ---------------- #

def detect_anomalies(df, model, scaler):
    print("🔍 Scoring anomalies...")

    X = scaler.transform(df[FEATURE_COLUMNS])

    results = df.copy()
    results["anomaly"] = model.predict(X)

    print("✔ Anomaly distribution:\n", results["anomaly"].value_counts())

    return results


# ---------------- MAIN ---------------- #

def main():
    print("\n====== MODEL TRAINING STARTED ======\n")

    df = get_training_frame(benign_only=True)

    # 🔥 Optional speed optimization (uncomment if slow)
    # df = df.sample(n=50000, random_state=42)

    model, scaler = train_isolation_forest(df)

    results = detect_anomalies(df, model, scaler)

    RESULTS_PATH.parent.mkdir(exist_ok=True)
    results.to_csv(RESULTS_PATH, index=False)

    print("\n====== DONE ======")
    print("Results saved to:", RESULTS_PATH)


if __name__ == "__main__":
    main()