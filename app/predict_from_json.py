import json
import sys
import joblib
try:
    from .features import MODEL_PATH, features_dataframe
except ImportError:
    from features import MODEL_PATH, features_dataframe


def main():
    # Read JSON passed from PHP (1 argument)
    if len(sys.argv) < 2:
        # Try reading from stdin as a fallback
        raw = sys.stdin.read().strip()
    else:
        raw = sys.argv[1]

    # Strip surrounding single or double quotes that may be added by shell quoting
    if raw and ((raw.startswith("'") and raw.endswith("'")) or (raw.startswith('"') and raw.endswith('"'))):
        raw = raw[1:-1]

    try:
        features = json.loads(raw)
    except json.JSONDecodeError:
        # Fallback: handle cases where shell removed double-quotes from keys
        import re
        # Add double quotes around keys (occurrences after { or , and before :)
        fixed = re.sub(r'(?<=\{|,)\s*([^:\s]+)\s*:', r'"\1":', raw)
        features = json.loads(fixed)

    model = joblib.load(MODEL_PATH)

    expected_columns = list(getattr(model, "feature_names_in_", [])) or list(
        getattr(model, "feature_columns_", [])
    )
    X = features_dataframe(features, expected_columns or None)
    pred = model.predict(X)[0]
    result = "PHISHING" if int(pred) == 1 else "LEGITIMATE"
    print(result)

if __name__ == "__main__":
    main()
