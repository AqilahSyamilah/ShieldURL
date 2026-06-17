import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

try:
    from bs4 import BeautifulSoup
except ImportError:  # Keep scan endpoints alive until requirements are installed.
    BeautifulSoup = None


logger = logging.getLogger("shieldurl.page_analyzer")

MAX_RESPONSE_BYTES = 512 * 1024
SUSPICIOUS_FILE_EXTENSIONS = [".exe", ".zip", ".scr", ".js", ".apk"]
LOGIN_KEYWORDS = ["login", "log in", "signin", "sign in", "password", "account"]
VERIFY_KEYWORDS = ["verify", "verification", "confirm", "validate", "update", "secure"]
BANK_PAYMENT_KEYWORDS = [
    "bank",
    "banking",
    "payment",
    "paypal",
    "card",
    "credit",
    "debit",
    "wallet",
    "billing",
    "invoice",
]


def _normalize_url(url: str) -> str:
    value = (url or "").strip()
    if value and not re.match(r"^https?://", value, re.I):
        value = "http://" + value
    return value


def _fallback(url: str, error: str = "") -> dict[str, Any]:
    return {
        "success": False,
        "error": error,
        "final_url": url,
        "redirect_count": 0,
        "http_status": None,
        "page_title": "",
        "has_form": False,
        "has_password_field": False,
        "has_email_field": False,
        "has_login_keywords": False,
        "has_verify_keywords": False,
        "has_bank_or_payment_keywords": False,
        "has_download_link": False,
        "suspicious_file_extensions": [],
        "external_form_action": False,
        "indicators_summary": [],
    }


def _read_limited_response(response: requests.Response) -> bytes:
    chunks = []
    total = 0
    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue
        remaining = MAX_RESPONSE_BYTES - total
        if remaining <= 0:
            break
        limited_chunk = chunk[:remaining]
        chunks.append(limited_chunk)
        total += len(limited_chunk)
        if total >= MAX_RESPONSE_BYTES:
            break
    return b"".join(chunks)


def _contains_any(text: str, keywords: list[str]) -> bool:
    lowered = text.lower()
    return any(keyword in lowered for keyword in keywords)


def _absolute_url(base_url: str, value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    return urljoin(base_url, value)


def _same_host(left_url: str, right_url: str) -> bool:
    left_host = (urlparse(left_url).hostname or "").lower()
    right_host = (urlparse(right_url).hostname or "").lower()
    return bool(left_host and right_host and left_host == right_host)


def _find_suspicious_extensions(values: list[str]) -> list[str]:
    found = set()
    for value in values:
        lowered = value.lower().split("?", 1)[0].split("#", 1)[0]
        for extension in SUSPICIOUS_FILE_EXTENSIONS:
            if lowered.endswith(extension) or re.search(rf"{re.escape(extension)}(?:$|[/?#])", lowered):
                found.add(extension)
    return sorted(found)


def _summarize(indicators: dict[str, Any]) -> list[str]:
    summary = []
    if indicators["redirect_count"] > 0:
        summary.append(f"Redirected {indicators['redirect_count']} time(s) before landing.")
    if indicators["has_password_field"]:
        summary.append("Page contains a password input field.")
    elif indicators["has_email_field"]:
        summary.append("Page contains an email input field.")
    if indicators["external_form_action"]:
        summary.append("A form submits to an external host.")
    if indicators["has_login_keywords"]:
        summary.append("Login/account keywords are present in page text.")
    if indicators["has_verify_keywords"]:
        summary.append("Verification/update keywords are present in page text.")
    if indicators["has_bank_or_payment_keywords"]:
        summary.append("Banking or payment keywords are present in page text.")
    if indicators["has_download_link"]:
        extensions = ", ".join(indicators["suspicious_file_extensions"]) or "suspicious extension"
        summary.append(f"Page links to downloadable content with {extensions}.")
    return summary[:8]


def analyze_page_indicators(url: str) -> dict[str, Any]:
    """Safely extract static HTML indicators without browser or JavaScript execution."""
    normalized_url = _normalize_url(url)
    if BeautifulSoup is None:
        return _fallback(normalized_url, "beautifulsoup4 is not installed")

    try:
        # Fetch the URL with redirects enabled so the scanner can record the final landing URL.
        response = requests.get(
            normalized_url,
            timeout=5,
            allow_redirects=True,
            stream=True,
            headers={
                "User-Agent": "ShieldURL-PageAnalyzer/1.0",
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
            },
        )

        final_url = response.url or normalized_url
        content_type = response.headers.get("Content-Type", "")
        base = _fallback(normalized_url)
        base.update({
            "success": True,
            "final_url": final_url,
            "redirect_count": len(response.history),
            "http_status": response.status_code,
        })

        # Skip files and other non-HTML responses because BeautifulSoup only scans page markup here.
        if "html" not in content_type.lower():
            base["error"] = f"Skipped non-HTML response: {content_type or 'unknown content type'}"
            base["indicators_summary"] = _summarize(base)
            response.close()
            return base

        raw_html = _read_limited_response(response)
        response.close()

        # beautifulsoup scanning section
        # Parse the downloaded HTML into a searchable DOM tree.
        soup = BeautifulSoup(raw_html, "html.parser")

        # Page title detection: captures the browser tab title for report context.
        title_tag = soup.find("title")
        page_title = re.sub(r"\s+", " ", title_tag.get_text(" ", strip=True)) if title_tag else ""

        # Form detection: phishing pages commonly include forms to collect submitted data.
        forms = soup.find_all("form")

        # Input detection: checks form fields for password/email collection signals.
        inputs = soup.find_all("input")

        # Visible text extraction: keyword checks run against readable page content.
        text = soup.get_text(" ", strip=True)

        # Link/script/form target collection: gathers URLs used by anchors, resources, and form actions.
        link_values = []

        for tag in soup.find_all(["a", "link", "script", "form"]):
            for attr in ["href", "src", "action"]:
                value = tag.get(attr)
                if value:
                    link_values.append(_absolute_url(final_url, str(value)))

        # Download lure detection: flags links ending in risky executable/archive extensions.
        suspicious_extensions = _find_suspicious_extensions(link_values)

        # External form action detection: flags forms that submit data to a different host.
        external_form_action = False
        for form in forms:
            action = _absolute_url(final_url, str(form.get("action") or ""))
            if action and not _same_host(final_url, action):
                external_form_action = True
                break

        # Store each detected page indicator so the API/report can explain why the URL looks risky.
        indicators = {
            "success": True,
            "error": "",
            "final_url": final_url,
            "redirect_count": len(response.history),
            "http_status": response.status_code,
            "page_title": page_title[:160],
            # True when at least one HTML form exists on the page.
            "has_form": bool(forms),
            # True when a password input exists, which is a strong credential-harvesting signal.
            "has_password_field": any(str(item.get("type", "")).lower() == "password" for item in inputs),
            # True when an email input/name/id exists, often used for login or account collection.
            "has_email_field": any(
                str(item.get("type", "")).lower() == "email"
                or "email" in str(item.get("name", "")).lower()
                or "email" in str(item.get("id", "")).lower()
                for item in inputs
            ),
            # True when login/account words appear in the visible page text.
            "has_login_keywords": _contains_any(text, LOGIN_KEYWORDS),
            # True when verify/update/security wording appears in the visible page text.
            "has_verify_keywords": _contains_any(text, VERIFY_KEYWORDS),
            # True when banking, card, invoice, or payment wording appears in the visible page text.
            "has_bank_or_payment_keywords": _contains_any(text, BANK_PAYMENT_KEYWORDS),
            # True when the page links to risky downloads or uses an HTML download attribute.
            "has_download_link": bool(suspicious_extensions)
            or any(tag.has_attr("download") for tag in soup.find_all("a")),
            # List of risky file extensions found in page links.
            "suspicious_file_extensions": suspicious_extensions,
            # True when a form sends submitted data away from the scanned page's host.
            "external_form_action": external_form_action,
            "indicators_summary": [],
        }
        # Convert raw booleans into short human-readable findings for the report.
        indicators["indicators_summary"] = _summarize(indicators)
        return indicators

    except Exception as exc:
        logger.warning("safe page indicator extraction failed for %s: %s", normalized_url, exc)
        return _fallback(normalized_url, str(exc))
