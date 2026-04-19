from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from model import DATASET_PATH, FEATURE_COLUMNS, get_training_frame


CLASSIFIER_PATH = Path("models") / "classifier.pkl"
CLASSIFIER_SCALER_PATH = Path("models") / "classifier_scaler.pkl"


def main():
    df = get_training_frame(DATASET_PATH, benign_only=False)
    if "label" not in df.columns:
        raise ValueError("attack_data.csv must include labels for classifier training.")

    X = df[FEATURE_COLUMNS]
    y = df["label"]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced",
    )
    model.fit(X_scaled, y)

    CLASSIFIER_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(model, CLASSIFIER_PATH)
    joblib.dump(scaler, CLASSIFIER_SCALER_PATH)

    print("Model trained successfully")


if __name__ == "__main__":
    main()
