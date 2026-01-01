import sys
import json
import joblib
import pandas as pd
import os

# Ensure model path is absolute (script may be invoked from different CWD)
MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'model', 'url_phishing_model.pkl'))

def main():
    # Read features JSON from argv or stdin
    if len(sys.argv) < 2:
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
        fixed = re.sub(r'(?<=\{|,)\s*([^:\s]+)\s*:', r'"\1":', raw)
        features = json.loads(fixed)

    # Allow overriding model path via second CLI arg (useful when invoked from other CWDs)
    if len(sys.argv) >= 3 and sys.argv[2]:
        mp = sys.argv[2]
        if mp and ((mp.startswith("'") and mp.endswith("'")) or (mp.startswith('"') and mp.endswith('"'))):
            mp = mp[1:-1]
        MODEL_PATH = mp

    # Debug: write model path to stderr to help diagnosing file path issues
    import sys as _sys
    try:
        _sys.stderr.write(f'MODEL_PATH_AT_RUNTIME={MODEL_PATH}\n')
    except Exception:
        pass

    model = joblib.load(MODEL_PATH)
    X = pd.DataFrame([features])

    # Predict label
    pred = model.predict(X)[0]

    # Predict probability if available
    confidence = None
    if hasattr(model, 'predict_proba'):
        try:
            proba = model.predict_proba(X)[0]
            # model.classes_ gives order
            classes = list(model.classes_)
            # confidence: probability of predicted class
            idx = classes.index(pred)
            confidence = float(proba[idx])
        except Exception:
            confidence = None

    result = {
        'status': 'LEGITIMATE' if int(pred) == 1 else 'PHISHING',
        'raw_label': int(pred),
        'confidence_score': confidence if confidence is not None else 0.0,
        'features': features
    }

    print(json.dumps(result))

if __name__ == '__main__':
    main()
