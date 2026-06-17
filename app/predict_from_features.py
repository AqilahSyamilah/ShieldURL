import json
import sys

import joblib

try:
    from .features import MODEL_PATH, features_dataframe
except ImportError:
    from features import MODEL_PATH, features_dataframe


def parse_features(raw: str) -> dict:
    if raw and ((raw.startswith("'") and raw.endswith("'")) or (raw.startswith('"') and raw.endswith('"'))):
        raw = raw[1:-1]

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        import re

        fixed = re.sub(r'(?<=\{|,)\s*([^:\s]+)\s*:', r'"\1":', raw)
        return json.loads(fixed)


def predict_features(features: dict, model_path: str = MODEL_PATH) -> dict:
    model = joblib.load(model_path)

    expected_columns = list(getattr(model, "feature_names_in_", [])) or list(
        getattr(model, "feature_columns_", [])
    )
    X = features_dataframe(features, expected_columns or None)

    prediction = int(model.predict(X)[0])
    phishing_probability = None
    confidence = 0.0

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X)[0]
        classes = list(model.classes_)
        confidence = float(probabilities[classes.index(prediction)])
        if 1 in classes:
            phishing_probability = float(probabilities[classes.index(1)])

    status = "PHISHING" if prediction == 1 else "LEGITIMATE"
    return {
        "status": status,
        "raw_label": prediction,
        "confidence_score": confidence,
        "phishing_probability": phishing_probability,
        "features": {column: int(X.iloc[0][column]) for column in X.columns},
    }


def main():
    raw = sys.argv[1] if len(sys.argv) >= 2 else sys.stdin.read().strip()
    features = parse_features(raw)
    model_path = sys.argv[2] if len(sys.argv) >= 3 and sys.argv[2] else MODEL_PATH
    result = predict_features(features, model_path)
    print(
        json.dumps(result)
    )


if __name__ == "__main__":
    main()
