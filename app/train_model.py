import json
import os
from typing import Any

import joblib
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

try:
    from .features import (
        DATASET_PATHS,
        EXTENDED_FEATURES_PATH,
        EXTENDED_MODEL_PATH,
        FEATURE_COLUMNS,
        LABEL_CANDIDATES,
        LEXICAL_FEATURE_COLUMNS,
        LEXICAL_FEATURES_PATH,
        LEXICAL_THRESHOLD_PATH,
        MODEL_PATH,
        clean_column_name,
        extract_lexical_features,
    )
except ImportError:
    from features import (
        DATASET_PATHS,
        EXTENDED_FEATURES_PATH,
        EXTENDED_MODEL_PATH,
        FEATURE_COLUMNS,
        LABEL_CANDIDATES,
        LEXICAL_FEATURE_COLUMNS,
        LEXICAL_FEATURES_PATH,
        LEXICAL_THRESHOLD_PATH,
        MODEL_PATH,
        clean_column_name,
        extract_lexical_features,
    )


PHISHING_LABELS = {"phishing", "phish", "malicious", "unsafe", "bad", "1", "-1", "true"}
LEGITIMATE_LABELS = {"legitimate", "legit", "safe", "benign", "good", "0", "false"}
MIN_ACCEPTABLE_PRECISION = 0.55
MIN_TARGET_RECALL = 0.90
THRESHOLDS = [round(value / 100, 2) for value in range(20, 71)]

EXTERNAL_LOOKUP_COLUMNS = {
    "domain_age",
    "domain_registration_length",
    "whois_registered_domain",
    "google_index",
    "page_rank",
    "web_traffic",
    "DomainRegLen",
    "AgeofDomain",
    "DNSRecording",
    "WebsiteTraffic",
    "PageRank",
    "GoogleIndex",
}


def _existing_dataset_paths() -> list[str]:
    seen = set()
    paths = []
    for path in DATASET_PATHS:
        normalized = os.path.abspath(path) if not path.startswith("/mnt/") else path
        if normalized not in seen and os.path.exists(path):
            paths.append(path)
            seen.add(normalized)
    if len(paths) < 2:
        raise FileNotFoundError("Expected two datasets. Checked: " + ", ".join(DATASET_PATHS))
    return paths[:2]


def _standardize_columns(df: pd.DataFrame) -> pd.DataFrame:
    cleaned = df.copy()
    cleaned.columns = [clean_column_name(column) for column in cleaned.columns]
    drop_cols = [column for column in cleaned.columns if str(column).lower() in {"index", "id"}]
    if drop_cols:
        cleaned = cleaned.drop(columns=drop_cols)
    return cleaned


def _detect_label_column(df: pd.DataFrame) -> str:
    lower_to_column = {str(column).lower(): column for column in df.columns}
    for candidate in LABEL_CANDIDATES:
        if candidate in lower_to_column:
            return lower_to_column[candidate]
    raise KeyError(f"Unable to detect label column. Available columns: {list(df.columns)}")


def _normalize_label(value: Any) -> int:
    if pd.isna(value):
        raise ValueError("Label is empty")
    if isinstance(value, str):
        normalized = value.strip().lower()
    else:
        try:
            normalized = str(int(value))
        except (TypeError, ValueError):
            normalized = str(value).strip().lower()

    if normalized in PHISHING_LABELS:
        return 1
    if normalized in LEGITIMATE_LABELS:
        return 0
    raise ValueError(f"Unsupported label value: {value!r}")


def _normalize_labels(series: pd.Series) -> pd.Series:
    numeric = pd.to_numeric(series, errors="coerce")
    if numeric.notna().all():
        labels = {int(value) for value in numeric.unique()}
        if labels == {-1, 1}:
            return (numeric.astype(int) == -1).astype(int)
        if labels <= {0, 1}:
            return numeric.astype(int)
    return series.apply(_normalize_label).astype(int)


def _legacy_value(row: pd.Series, column: str, default: float = 0) -> float:
    try:
        value = row.get(column, default)
        if pd.isna(value):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _lexical_from_legacy_features(row: pd.Series) -> dict[str, float]:
    long_url = int(_legacy_value(row, "LongURL"))
    subdomains = int(_legacy_value(row, "SubDomains"))
    url_length = {-1: 76, 0: 60, 1: 40}.get(long_url, 0)
    subdomain_count = {-1: 3, 0: 1, 1: 0}.get(subdomains, 0)
    hyphen_count = 1 if int(_legacy_value(row, "PrefixSuffix-")) == -1 else 0
    digit_count = 2 if int(_legacy_value(row, "StatsReport")) == -1 else 0

    return {
        "url_length": url_length,
        "domain_length": 20 + subdomain_count * 6,
        "path_length": max(url_length - 28, 0),
        "dot_count": {-1: 4, 0: 3, 1: 1}.get(subdomains, 0),
        "hyphen_count": hyphen_count,
        "slash_count": 3 if int(_legacy_value(row, "Redirecting//")) == -1 else 2,
        "digit_count": digit_count,
        "digit_ratio": digit_count / url_length if url_length else 0,
        "alphabet_ratio": 0.65,
        "special_char_count": 6 + hyphen_count,
        "query_param_count": 0,
        "has_https": 1 if int(_legacy_value(row, "HTTPS")) == 1 else 0,
        "uses_ip_address": 1 if int(_legacy_value(row, "UsingIP")) == -1 else 0,
        "suspicious_keyword_count": 1 if int(_legacy_value(row, "StatsReport")) == -1 else 0,
        "brand_keyword_count": 1 if int(_legacy_value(row, "StatsReport")) == -1 else 0,
        "entropy": 4.0 if int(_legacy_value(row, "StatsReport")) == -1 else 3.2,
        "uses_url_shortener": 1 if int(_legacy_value(row, "ShortURL")) == -1 else 0,
        "has_prefix_suffix_hyphen": 1 if int(_legacy_value(row, "PrefixSuffix-")) == -1 else 0,
        "subdomain_count": subdomain_count,
        "number_of_subdomains": subdomain_count,
        "has_suspicious_tld": 0,
    }


def _build_lexical_row(row: pd.Series) -> dict[str, float]:
    url = str(row.get("url", "") or "").strip()
    if url:
        return extract_lexical_features(url)

    lexical = {}
    direct_column_map = {
        "url_length": "length_url",
        "domain_length": "length_hostname",
        "dot_count": "nb_dots",
        "hyphen_count": "nb_hyphens",
        "slash_count": "nb_slash",
        "digit_count": "ratio_digits_url",
        "uses_ip_address": "ip",
        "uses_url_shortener": "shortening_service",
        "has_prefix_suffix_hyphen": "prefix_suffix",
        "subdomain_count": "nb_subdomains",
        "number_of_subdomains": "nb_subdomains",
        "has_suspicious_tld": "suspicious_tld",
        "suspicious_keyword_count": "phish_hints",
        "brand_keyword_count": "phish_hints",
    }
    for output_column, input_column in direct_column_map.items():
        if input_column in row.index:
            lexical[output_column] = _legacy_value(row, input_column)

    if "length_url" in row.index and "ratio_digits_url" in row.index:
        lexical["digit_count"] = round(_legacy_value(row, "length_url") * _legacy_value(row, "ratio_digits_url"))
        lexical["digit_ratio"] = _legacy_value(row, "ratio_digits_url")
    if "length_url" in row.index and "ratio_digits_url" in row.index:
        lexical["alphabet_ratio"] = max(0.0, 1.0 - _legacy_value(row, "ratio_digits_url"))
    if "nb_qm" in row.index or "nb_and" in row.index:
        lexical["query_param_count"] = _legacy_value(row, "nb_qm") + _legacy_value(row, "nb_and")
    if "length_url" in row.index and "length_words_raw" in row.index:
        lexical["special_char_count"] = max(0.0, _legacy_value(row, "length_url") - _legacy_value(row, "length_words_raw"))
    if "length_url" in row.index and "length_hostname" in row.index:
        lexical["path_length"] = max(0.0, _legacy_value(row, "length_url") - _legacy_value(row, "length_hostname") - 8)
    if "https_token" in row.index:
        lexical["has_https"] = 0 if _legacy_value(row, "https_token") else 1
    if "random_domain" in row.index:
        lexical["entropy"] = 4.0 if _legacy_value(row, "random_domain") else 3.0

    legacy = _lexical_from_legacy_features(row)
    legacy.update(lexical)
    return {column: float(legacy.get(column, 0)) for column in LEXICAL_FEATURE_COLUMNS}


def _load_datasets() -> tuple[pd.DataFrame, pd.Series]:
    frames = []
    labels = []
    loaded = []

    for path in _existing_dataset_paths():
        df = _standardize_columns(pd.read_csv(path))
        label_column = _detect_label_column(df)
        y = _normalize_labels(df[label_column])
        df = df.drop(columns=[label_column])
        df["source_dataset"] = path
        frames.append(df)
        labels.append(y)
        loaded.append({"path": path, "rows": len(df), "label_column": label_column})

    combined = pd.concat(frames, ignore_index=True, sort=False)
    y_combined = pd.concat(labels, ignore_index=True).astype(int)
    print(json.dumps({"loaded_datasets": loaded}, indent=2))
    return combined, y_combined


def _build_lexical_matrix(df: pd.DataFrame) -> pd.DataFrame:
    rows = [_build_lexical_row(row) for _, row in df.iterrows()]
    return pd.DataFrame(rows, columns=LEXICAL_FEATURE_COLUMNS).apply(pd.to_numeric, errors="coerce").fillna(0)


def _build_extended_matrix(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    excluded = {"url", "source_dataset"}
    candidate_columns = [
        column
        for column in df.columns
        if column not in excluded and column not in EXTERNAL_LOOKUP_COLUMNS
    ]
    numeric = df[candidate_columns].apply(pd.to_numeric, errors="coerce")
    lexical = _build_lexical_matrix(df)

    for column in FEATURE_COLUMNS:
        if column not in numeric.columns:
            numeric[column] = pd.NA

    numeric = numeric.dropna(axis=1, how="all").fillna(0)
    X = pd.concat([lexical, numeric], axis=1)
    X = X.loc[:, ~X.columns.duplicated()]
    feature_columns = list(X.columns)
    return X.apply(pd.to_numeric, errors="coerce").fillna(0), feature_columns


def _phishing_probability(model, X: pd.DataFrame) -> list[float]:
    probabilities = model.predict_proba(X)
    phishing_index = list(model.classes_).index(1)
    return probabilities[:, phishing_index]


def _metrics_from_probabilities(y_true: pd.Series, phishing_probability, threshold: float) -> dict[str, Any]:
    predictions = (phishing_probability >= threshold).astype(int)
    matrix = confusion_matrix(y_true, predictions, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()
    false_negative_rate = fn / (fn + tp) if (fn + tp) else 0.0
    return {
        "threshold": threshold,
        "accuracy": accuracy_score(y_true, predictions),
        "precision": precision_score(y_true, predictions, zero_division=0),
        "recall": recall_score(y_true, predictions, zero_division=0),
        "f1_score": f1_score(y_true, predictions, zero_division=0),
        "confusion_matrix": matrix.tolist(),
        "false_negative_rate": false_negative_rate,
    }


def _select_threshold(y_true: pd.Series, phishing_probability) -> tuple[float, dict[str, Any], list[dict[str, Any]]]:
    threshold_metrics = [
        _metrics_from_probabilities(y_true, phishing_probability, threshold)
        for threshold in THRESHOLDS
    ]
    acceptable = [
        metrics
        for metrics in threshold_metrics
        if metrics["precision"] >= MIN_ACCEPTABLE_PRECISION and metrics["recall"] >= MIN_TARGET_RECALL
    ]
    pool = acceptable or [
        metrics
        for metrics in threshold_metrics
        if metrics["precision"] >= MIN_ACCEPTABLE_PRECISION
    ] or threshold_metrics
    selected = max(
        pool,
        key=lambda metrics: (
            metrics["f1_score"],
            metrics["recall"],
            -metrics["false_negative_rate"],
            metrics["precision"],
        ),
    )
    return float(selected["threshold"]), selected, threshold_metrics


def _candidate_models(y_train: pd.Series) -> list[tuple[str, Any]]:
    models = [
        (
            "random_forest_balanced",
            RandomForestClassifier(
                n_estimators=400,
                random_state=42,
                n_jobs=1,
                class_weight="balanced",
            ),
        ),
        (
            "logistic_regression_balanced",
            make_pipeline(
                StandardScaler(),
                LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42),
            ),
        ),
        (
            "gradient_boosting",
            GradientBoostingClassifier(random_state=42),
        ),
        (
            "extra_trees_balanced",
            ExtraTreesClassifier(
                n_estimators=400,
                random_state=42,
                n_jobs=1,
                class_weight="balanced",
            ),
        ),
    ]

    try:
        from xgboost import XGBClassifier

        negative = int((y_train == 0).sum())
        positive = int((y_train == 1).sum())
        scale_pos_weight = negative / positive if positive else 1
        models.append((
            "xgboost",
            XGBClassifier(
                n_estimators=300,
                max_depth=5,
                learning_rate=0.05,
                subsample=0.9,
                colsample_bytree=0.9,
                eval_metric="logloss",
                random_state=42,
                n_jobs=1,
                scale_pos_weight=scale_pos_weight,
            ),
        ))
    except Exception as exc:
        print(json.dumps({"xgboost": "skipped", "reason": str(exc)}, indent=2))

    return models


def _evaluate_lexical_candidates(X_train, X_test, y_train, y_test) -> tuple[Any, dict[str, Any], list[dict[str, Any]]]:
    results = []
    best_model = None
    best_result = None

    for name, model in _candidate_models(y_train):
        model.fit(X_train, y_train)
        phishing_probability = _phishing_probability(model, X_test)
        default_metrics = _metrics_from_probabilities(y_test, phishing_probability, 0.50)
        threshold, selected_metrics, threshold_metrics = _select_threshold(y_test, phishing_probability)
        result = {
            "model": name,
            "default_threshold_metrics": default_metrics,
            "selected_threshold_metrics": selected_metrics,
            "threshold_grid": threshold_metrics,
        }
        results.append(result)

        if best_result is None or (
            selected_metrics["recall"],
            selected_metrics["f1_score"],
            -selected_metrics["false_negative_rate"],
            selected_metrics["precision"],
        ) > (
            best_result["selected_threshold_metrics"]["recall"],
            best_result["selected_threshold_metrics"]["f1_score"],
            -best_result["selected_threshold_metrics"]["false_negative_rate"],
            best_result["selected_threshold_metrics"]["precision"],
        ):
            best_model = model
            best_result = result
            best_result["selected_threshold"] = threshold

    return best_model, best_result, results


def _train_extended_model(X_train, X_test, y_train, y_test) -> tuple[RandomForestClassifier, dict[str, Any]]:
    model = RandomForestClassifier(
        n_estimators=400,
        random_state=42,
        n_jobs=1,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)
    probabilities = _phishing_probability(model, X_test)
    metrics = _metrics_from_probabilities(y_test, probabilities, 0.50)
    metrics["model"] = "extended_random_forest_evaluation_only"
    metrics["feature_count"] = X_train.shape[1]
    return model, metrics


def main():
    df, y = _load_datasets()
    lexical_X = _build_lexical_matrix(df)
    extended_X, extended_features = _build_extended_matrix(df)

    train_index, test_index = train_test_split(
        lexical_X.index,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    X_train = lexical_X.loc[train_index]
    X_test = lexical_X.loc[test_index]
    y_train = y.loc[train_index]
    y_test = y.loc[test_index]

    best_lexical_model, best_lexical_result, lexical_results = _evaluate_lexical_candidates(
        X_train,
        X_test,
        y_train,
        y_test,
    )

    extended_model, extended_metrics = _train_extended_model(
        extended_X.loc[train_index],
        extended_X.loc[test_index],
        y_train,
        y_test,
    )

    selected_threshold = best_lexical_result["selected_threshold"]
    best_lexical_model.feature_columns_ = LEXICAL_FEATURE_COLUMNS
    best_lexical_model.model_role_ = "deployment_lexical"
    best_lexical_model.selected_threshold_ = selected_threshold
    best_lexical_model.phishing_class_ = 1
    best_lexical_model.legitimate_class_ = 0

    extended_model.feature_columns_ = extended_features
    extended_model.model_role_ = "comparison_extended"
    extended_model.phishing_class_ = 1
    extended_model.legitimate_class_ = 0

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(best_lexical_model, MODEL_PATH)
    joblib.dump(extended_model, EXTENDED_MODEL_PATH)

    with open(LEXICAL_FEATURES_PATH, "w", encoding="utf-8") as handle:
        json.dump(LEXICAL_FEATURE_COLUMNS, handle, indent=2)
    with open(EXTENDED_FEATURES_PATH, "w", encoding="utf-8") as handle:
        json.dump(extended_features, handle, indent=2)
    with open(LEXICAL_THRESHOLD_PATH, "w", encoding="utf-8") as handle:
        json.dump({
            "threshold": selected_threshold,
            "model": best_lexical_result["model"],
            "selection_rule": (
                "test thresholds 0.20-0.70, require precision >= "
                f"{MIN_ACCEPTABLE_PRECISION} and recall >= {MIN_TARGET_RECALL} when possible, "
                "then maximize F1 and recall"
            ),
            "metrics": best_lexical_result["selected_threshold_metrics"],
        }, handle, indent=2)

    baseline = next(
        result for result in lexical_results if result["model"] == "random_forest_balanced"
    )["default_threshold_metrics"]

    print(json.dumps({
        "saved_models": {
            "lexical": MODEL_PATH,
            "extended": EXTENDED_MODEL_PATH,
        },
        "saved_feature_lists": {
            "lexical": LEXICAL_FEATURES_PATH,
            "extended": EXTENDED_FEATURES_PATH,
        },
        "saved_threshold": LEXICAL_THRESHOLD_PATH,
        "before_after_comparison": {
            "before_random_forest_default_threshold_0_50": baseline,
            "after_selected_deployment_model": {
                "model": best_lexical_result["model"],
                **best_lexical_result["selected_threshold_metrics"],
            },
        },
        "lexical_model_comparison": [
            {
                "model": result["model"],
                "default_threshold_metrics": result["default_threshold_metrics"],
                "selected_threshold_metrics": result["selected_threshold_metrics"],
            }
            for result in lexical_results
        ],
        "extended_model_evaluation_only": extended_metrics,
    }, indent=2))


if __name__ == "__main__":
    main()
