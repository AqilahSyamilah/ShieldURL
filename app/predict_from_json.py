import json
import sys
import joblib
import pandas as pd

MODEL_PATH = "model/url_phishing_model.pkl"

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

    X = pd.DataFrame([features])
    pred = model.predict(X)[0]     # will be 1 or -1

    # IMPORTANT: dataset meaning
    # 1 = Legitimate, -1 = Phishing
    result = "LEGITIMATE" if int(pred) == 1 else "PHISHING"
    print(result)

if __name__ == "__main__":
    main()
