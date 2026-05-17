import os
import re
from typing import Any, Optional
from urllib.parse import urlparse

import pandas as pd


MODEL_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "model", "url_phishing_model.pkl")
)
DATASET_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "data", "PhishingData.csv")
)

FEATURE_COLUMNS = [
    "UsingIP",
    "LongURL",
    "ShortURL",
    "Symbol@",
    "Redirecting//",
    "PrefixSuffix-",
    "SubDomains",
    "HTTPS",
    "DomainRegLen",
    "Favicon",
    "NonStdPort",
    "HTTPSDomainURL",
    "RequestURL",
    "AnchorURL",
    "LinksInScriptTags",
    "ServerFormHandler",
    "InfoEmail",
    "AbnormalURL",
    "WebsiteForwarding",
    "StatusBarCust",
    "DisableRightClick",
    "UsingPopupWindow",
    "IframeRedirection",
    "AgeofDomain",
    "DNSRecording",
    "WebsiteTraffic",
    "PageRank",
    "GoogleIndex",
    "LinksPointingToPage",
    "StatsReport",
]

LABEL_CANDIDATES = ["Result", "class", "Class", "Label", "label", "target", "Target"]

RAW_TO_CANONICAL = {
    "having_IPhaving_IP_Address": "UsingIP",
    "having_IP_Address": "UsingIP",
    "URLURL_Length": "LongURL",
    "URL_Length": "LongURL",
    "Shortining_Service": "ShortURL",
    "having_At_Symbol": "Symbol@",
    "double_slash_redirecting": "Redirecting//",
    "Prefix_Suffix": "PrefixSuffix-",
    "having_Sub_Domain": "SubDomains",
    "SSLfinal_State": "HTTPS",
    "Domain_registeration_length": "DomainRegLen",
    "Favicon": "Favicon",
    "port": "NonStdPort",
    "HTTPS_token": "HTTPSDomainURL",
    "Request_URL": "RequestURL",
    "URL_of_Anchor": "AnchorURL",
    "Links_in_tags": "LinksInScriptTags",
    "SFH": "ServerFormHandler",
    "Submitting_to_email": "InfoEmail",
    "Abnormal_URL": "AbnormalURL",
    "Redirect": "WebsiteForwarding",
    "on_mouseover": "StatusBarCust",
    "RightClick": "DisableRightClick",
    "popUpWidnow": "UsingPopupWindow",
    "Iframe": "IframeRedirection",
    "age_of_domain": "AgeofDomain",
    "DNSRecord": "DNSRecording",
    "web_traffic": "WebsiteTraffic",
    "Page_Rank": "PageRank",
    "Google_Index": "GoogleIndex",
    "Links_pointing_to_page": "LinksPointingToPage",
    "Statistical_report": "StatsReport",
    "Result": "Result",
}

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "tiny.cc",
    "bit.do",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
}

SUSPICIOUS_KEYWORDS = {"secure", "account", "update", "login", "verify", "signin", "banking", "wallet"}


def clean_column_name(name: Any) -> str:
    text = str(name).strip()
    return RAW_TO_CANONICAL.get(text, text)


def clean_dataset_frame(df: pd.DataFrame) -> tuple[pd.DataFrame, str]:
    cleaned = df.copy()
    cleaned.columns = [clean_column_name(col) for col in cleaned.columns]

    drop_cols = [col for col in cleaned.columns if col.lower() in {"index", "id"}]
    if drop_cols:
        cleaned = cleaned.drop(columns=drop_cols)

    target_column = next((col for col in LABEL_CANDIDATES if col in cleaned.columns), None)
    if not target_column:
        raise KeyError(f"Unable to detect target column. Available columns: {list(cleaned.columns)}")

    missing = [col for col in FEATURE_COLUMNS if col not in cleaned.columns]
    if missing:
        raise KeyError(f"Dataset missing required feature columns after cleaning: {missing}")

    ordered = cleaned[FEATURE_COLUMNS + [target_column]].copy()
    ordered[FEATURE_COLUMNS] = ordered[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")
    ordered[target_column] = pd.to_numeric(ordered[target_column], errors="coerce")
    ordered = ordered.dropna(subset=FEATURE_COLUMNS + [target_column])
    ordered[FEATURE_COLUMNS] = ordered[FEATURE_COLUMNS].astype(int)
    ordered[target_column] = ordered[target_column].astype(int)
    return ordered, target_column


def load_clean_dataset(csv_path: str = DATASET_PATH) -> tuple[pd.DataFrame, str]:
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found at: {csv_path}")
    df = pd.read_csv(csv_path)
    return clean_dataset_frame(df)


def normalize_url(url: str) -> str:
    value = (url or "").strip()
    if value and not re.match(r"^https?://", value, re.I):
        value = "http://" + value
    return value


def normalize_host(host: str) -> str:
    host = (host or "").lower().strip()
    if host.startswith("www."):
        host = host[4:]
    return host


def get_domain(url: str) -> str:
    return normalize_host(urlparse(normalize_url(url)).hostname or "")


def _has_ip(host: str) -> bool:
    ipv4 = r"(?:\d{1,3}\.){3}\d{1,3}"
    ipv6 = r"(?:[a-fA-F0-9]{1,4}:){2,}[a-fA-F0-9]{1,4}"
    return bool(re.fullmatch(f"(?:{ipv4}|{ipv6})", host or ""))


def extract_features(url: str) -> dict[str, int]:
    normalized_url = normalize_url(url)
    parsed = urlparse(normalized_url)
    host = normalize_host(parsed.hostname or "")
    query = parsed.query or ""
    port = parsed.port
    dots = host.count(".")
    hyphen_count = host.count("-")
    keyword_hits = sum(1 for keyword in SUSPICIOUS_KEYWORDS if keyword in normalized_url.lower())

    if len(normalized_url) < 54:
        long_url = 1
    elif len(normalized_url) <= 75:
        long_url = 0
    else:
        long_url = -1

    if dots <= 1:
        subdomains = 1
    elif dots == 2:
        subdomains = 0
    else:
        subdomains = -1

    redirect_count = normalized_url.lower().count("//") - 1
    if redirect_count <= 0:
        forwarding = 1
    elif redirect_count == 1:
        forwarding = 0
    else:
        forwarding = -1

    return {
        "UsingIP": -1 if _has_ip(host) else 1,
        "LongURL": long_url,
        "ShortURL": -1 if host in SHORTENERS else 1,
        "Symbol@": -1 if "@" in normalized_url else 1,
        "Redirecting//": -1 if normalized_url.rfind("//") > 7 else 1,
        "PrefixSuffix-": -1 if "-" in host else 1,
        "SubDomains": subdomains,
        "HTTPS": 1 if parsed.scheme.lower() == "https" else -1,
        "DomainRegLen": 0,
        "Favicon": 0,
        "NonStdPort": 1 if port in (None, 80, 443) else -1,
        "HTTPSDomainURL": -1 if "https" in host else 1,
        "RequestURL": 0,
        "AnchorURL": 0,
        "LinksInScriptTags": 0,
        "ServerFormHandler": 0,
        "InfoEmail": -1 if "mailto:" in normalized_url.lower() else 1,
        "AbnormalURL": -1 if not host else 1,
        "WebsiteForwarding": forwarding,
        "StatusBarCust": -1 if "onmouseover" in normalized_url.lower() else 1,
        "DisableRightClick": 0,
        "UsingPopupWindow": 0,
        "IframeRedirection": 0,
        "AgeofDomain": 0,
        "DNSRecording": 1 if host else -1,
        "WebsiteTraffic": 0,
        "PageRank": 0,
        "GoogleIndex": 1 if host else -1,
        "LinksPointingToPage": 0,
        "StatsReport": -1 if keyword_hits >= 2 else 0,
    }


def features_dataframe(features: dict[str, int], expected_columns: Optional[list[str]] = None) -> pd.DataFrame:
    columns = expected_columns or FEATURE_COLUMNS
    row = {column: int(features.get(column, 0)) for column in columns}
    return pd.DataFrame([row], columns=columns)
