import json

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

try:
    from .features import DATASET_PATH, FEATURE_COLUMNS, MODEL_PATH, load_clean_dataset
except ImportError:
    from features import DATASET_PATH, FEATURE_COLUMNS, MODEL_PATH, load_clean_dataset


def resolve_label_mapping(series):
    labels = sorted(set(int(value) for value in series.unique()))
    if set(labels) == {-1, 1}:
        phishing_label = -1
        legitimate_label = 1
    elif set(labels) == {0, 1}:
        phishing_label = 1
        legitimate_label = 0
    else:
        raise ValueError(f"Unexpected label values: {labels}")
    y = (series.astype(int) == phishing_label).astype(int)
    return y, phishing_label, legitimate_label


def main():
    df, target_column = load_clean_dataset(DATASET_PATH)
    X = df[FEATURE_COLUMNS].copy()
    y, phishing_label, legitimate_label = resolve_label_mapping(df[target_column])

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=400,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)

    model.feature_columns_ = FEATURE_COLUMNS
    model.target_column_ = target_column
    model.source_dataset_ = DATASET_PATH
    model.phishing_label_ = phishing_label
    model.legitimate_label_ = legitimate_label
    model.phishing_class_ = 1
    model.legitimate_class_ = 0
    model.test_accuracy_ = accuracy

    joblib.dump(model, MODEL_PATH)

    summary = {
        "dataset_path": DATASET_PATH,
        "model_path": MODEL_PATH,
        "target_column": target_column,
        "accuracy": accuracy,
        "feature_count": len(FEATURE_COLUMNS),
        "features": FEATURE_COLUMNS,
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
        "classification_report": classification_report(y_test, predictions, digits=4, output_dict=True),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
