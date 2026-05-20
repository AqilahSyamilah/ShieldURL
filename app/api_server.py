import logging
import os
import re
import time
import traceback
from collections import defaultdict, deque
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, model_validator, validator

try:
    from .features import MODEL_PATH
    from .scan_url import run_scan
    from .llm_service import fallback_llm_report
    from .llm.chain import generate_chat_answer, generate_ir_report
except ImportError:
    from features import MODEL_PATH
    from scan_url import run_scan
    from llm_service import fallback_llm_report
    from llm.chain import generate_chat_answer, generate_ir_report

app = FastAPI(title="ShieldURL API", version="1.0")
logger = logging.getLogger("shieldurl.api")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

CHAT_RATE_LIMIT = 12
CHAT_RATE_WINDOW_SECONDS = 60
_chat_requests: dict[str, deque[float]] = defaultdict(deque)
CHAT_FALLBACK_ANSWER = (
    "The assistant timed out. The scan result is still valid; follow the displayed recommended actions."
)


@app.on_event("startup")
def warm_ollama():
    logger.info("chat ollama warmup skipped")
SENSITIVE_VALUE_PATTERN = re.compile(
    r"(?i)\b(password|passcode|otp|one[-\s]?time code|pin|card number|cvv|token|secret)\b\s*(?:is|=|:)?\s*[\w\-@.]{2,}"
)
CARD_LIKE_PATTERN = re.compile(r"\b(?:\d[ -]?){12,19}\b")
SENSITIVE_WORD_PATTERN = re.compile(
    r"(?i)\b(password|passcode|otp|one[-\s]?time code|pin|bank(?:ing)?|card number|cvv|token|secret)\b"
)


def _json_response(payload: dict, status_code: int = 200) -> JSONResponse:
    return JSONResponse(content=jsonable_encoder(payload), status_code=status_code)


class ScanRequest(BaseModel):
    url: str
    clicked: Optional[bool] = None
    generate_llm: bool = False


class LLMReportRequest(BaseModel):
    url: str
    clicked: Optional[bool] = None
    verdict: str
    confidence: float
    risk: str


class ChatRequest(BaseModel):
    scan_id: Optional[str] = None
    message: str = Field(default="", max_length=500)
    assistant_response_style: str = Field(default="simple")
    scan_context: dict = Field(default_factory=dict)
    conversation: list[dict] = Field(default_factory=list)
    history: list[dict] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def normalize_chat_aliases(cls, values):
        if not isinstance(values, dict):
            return values
        if not values.get("message"):
            for alias in ("user_question", "prompt", "question"):
                if values.get(alias):
                    values["message"] = values[alias]
                    break
        if not values.get("conversation") and values.get("history"):
            values["conversation"] = values["history"]
        if "history" not in values:
            values["history"] = values.get("conversation", [])
        return values

    @validator("message")
    def validate_message(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("message must be a string")
        value = value.strip()
        if not value:
            raise ValueError("message cannot be empty")
        if len(value) > 500:
            raise ValueError("message must be 500 characters or fewer")
        return value

    @validator("assistant_response_style")
    def validate_assistant_response_style(cls, value: str) -> str:
        if not isinstance(value, str):
            return "simple"
        normalized = value.strip().lower()
        if normalized not in {"simple", "technical", "executive"}:
            return "simple"
        return normalized


def _rate_limited(key: str) -> bool:
    now = time.time()
    bucket = _chat_requests[key]
    while bucket and now - bucket[0] > CHAT_RATE_WINDOW_SECONDS:
        bucket.popleft()
    if len(bucket) >= CHAT_RATE_LIMIT:
        return True
    bucket.append(now)
    return False


def _redact_for_log(value: str) -> str:
    value = SENSITIVE_VALUE_PATTERN.sub("[REDACTED]", value)
    value = CARD_LIKE_PATTERN.sub("[REDACTED]", value)
    value = SENSITIVE_WORD_PATTERN.sub("[REDACTED]", value)
    return value[:160]


def _chat_context_is_risky(scan_context: dict) -> bool:
    detection = scan_context.get("detection") if isinstance(scan_context, dict) else {}
    if not isinstance(detection, dict):
        detection = {}
    decision = " ".join(str(item).lower() for item in [
        detection.get("final_verdict"),
        detection.get("risk_level"),
        scan_context.get("final_verdict") if isinstance(scan_context, dict) else "",
        scan_context.get("risk_level") if isinstance(scan_context, dict) else "",
    ])
    return any(term in decision for term in ["phishing", "suspicious", "medium", "high"])


def _valid_scan_context(scan_context: dict) -> bool:
    if not isinstance(scan_context, dict) or not scan_context:
        return False
    detection = scan_context.get("detection")
    return bool(scan_context.get("checked_url")) and isinstance(detection, dict) and bool(detection.get("final_verdict"))


def _answer_softens_risky_verdict(answer: str) -> bool:
    normalized = answer.lower()
    unsafe_phrases = [
        "safe to open",
        "safe to visit",
        "you can open",
        "go ahead and open",
        "not dangerous",
        "not phishing",
        "false positive",
        "ignore the warning",
    ]
    return any(phrase in normalized for phrase in unsafe_phrases)


def _answer_refuses_help(answer: str) -> bool:
    normalized = answer.lower()
    refusal_phrases = [
        "cannot provide information",
        "can't provide information",
        "can i help you with something else",
        "i cannot assist",
        "i can't assist",
    ]
    return any(phrase in normalized for phrase in refusal_phrases)


def _answer_has_placeholder_text(answer: str) -> bool:
    normalized = answer.lower()
    placeholder_terms = [
        "action 1",
        "action 2",
        "recommendation 1",
        "recommendation 2",
        "practical containment step",
        "practical investigation step",
        "placeholder",
        "example output",
        "sample label",
        "generic template",
    ]
    return any(term in normalized for term in placeholder_terms)


def _question_asks_to_open(question: str) -> bool:
    normalized = question.lower()
    return any(phrase in normalized for phrase in [
        "can i open",
        "should i open",
        "safe to open",
        "can i visit",
        "should i visit",
        "can i click",
        "should i click",
        "safe to click",
        "can i access",
        "should i access",
        "okay if i access",
        "okay to access",
        "okay if i open",
        "okay to open",
        "safe to access",
        "is it safe",
        "open this",
        "visit this",
        "click this",
        "access this",
    ])


def _question_asks_why_dangerous(question: str) -> bool:
    normalized = question.lower()
    return any(phrase in normalized for phrase in ["why is", "why dangerous", "why is this url dangerous", "why is this url phishing", "why phishing"])


def _question_asks_clicked_advice(question: str) -> bool:
    normalized = question.lower()
    return "clicked" in normalized or "opened it" in normalized or "visited it" in normalized


def _question_asks_it_admin(question: str) -> bool:
    normalized = question.lower()
    return "it admin" in normalized or "admin do" in normalized or "it team" in normalized or "administrator" in normalized


def _question_asks_confidence(question: str) -> bool:
    normalized = question.lower()
    return "confidence" in normalized or "score" in normalized or "percentage" in normalized


def _question_asks_mitre(question: str) -> bool:
    normalized = question.lower()
    return any(term in normalized for term in ["mitre", "attack", "t1566", "spearphishing", "spear phishing"])


def _question_asks_indicators(question: str) -> bool:
    normalized = question.lower()
    return any(term in normalized for term in ["indicator", "signal", "evidence", "detected", "reason"])


def _question_asks_verdict_or_risk(question: str) -> bool:
    normalized = question.lower()
    return any(term in normalized for term in ["verdict", "status", "risk", "safe or phishing", "result"])


def _question_asks_phishing_definition(question: str) -> bool:
    normalized = question.lower()
    return "what is phishing" in normalized or "define phishing" in normalized or "phishing mean" in normalized


SCAN_TERM_EXPLANATIONS = {
    "url status": (
        "URL Status is the user-facing safety result for the scanned link.",
        "It summarizes whether ShieldURL sees the URL as safe, suspicious, or phishing.",
    ),
    "confidence score": (
        "Confidence Score shows how strongly ShieldURL supports the current verdict.",
        "A higher percentage means the scan signals more strongly support the displayed result.",
    ),
    "risk level": (
        "Risk Level translates the scan result into low, medium, or high operational risk.",
        "It helps decide how urgently users or IT should respond.",
    ),
    "mitre technique": (
        "MITRE Technique maps the URL behavior to a known attacker technique when applicable.",
        "For phishing links, ShieldURL commonly uses T1566.002 Spearphishing Link.",
    ),
    "checked url": (
        "Checked URL is the exact link submitted for scanning.",
        "It is shown so users can confirm which destination the result applies to.",
    ),
    "scan decision explanation": (
        "Scan Decision Explanation breaks down why the result was displayed.",
        "It includes probability, sensitivity, system detection, and user-facing safety status.",
    ),
    "phishing probability": (
        "Phishing Probability estimates how likely the URL patterns look like phishing.",
        "It is one signal used to support the final scan decision.",
    ),
    "detection sensitivity": (
        "Detection Sensitivity is the threshold used by ShieldURL when deciding whether URL signals are risky enough to flag.",
        "Higher sensitivity catches more suspicious patterns, while lower sensitivity is stricter about what gets flagged.",
    ),
    "system detection": (
        "System Detection is the internal machine result before it is converted into user-friendly wording.",
        "It may show values such as safe, suspicious, or phishing.",
    ),
    "safety status": (
        "Safety Status is the final user-facing wording shown to the user.",
        "It may soften uncertain cases, such as showing potentially suspicious instead of confirmed phishing.",
    ),
    "incident summary": (
        "Incident Summary explains the likely security concern in plain language.",
        "It should describe risk and impact without claiming compromise happened unless evidence exists.",
    ),
    "recommended actions": (
        "Recommended Actions are the immediate steps users or IT should take after the scan.",
        "They are based on the displayed verdict and risk level.",
    ),
    "nist response": (
        "NIST Response groups actions using incident-response phases.",
        "It can include detection, containment, recovery, and post-incident follow-up.",
    ),
    "technical analysis details": (
        "Technical Analysis Details show supporting scan signals and extracted URL features.",
        "They help explain the result but should not override the final verdict.",
    ),
    "mitre att&ck tags": (
        "MITRE ATT&CK Tags are standardized labels for attacker behavior.",
        "They help analysts classify the type of threat pattern seen in the scan.",
    ),
    "analyzed at": (
        "Analyzed At is the timestamp when ShieldURL produced the scan result.",
        "It helps confirm whether the result is current or from history.",
    ),
    "verdict": (
        "Verdict is the authoritative scan decision for the URL.",
        "It should not be changed by the assistant.",
    ),
    "phishing": (
        "Phishing means the URL appears designed to deceive users or steal sensitive information.",
        "Users should avoid entering passwords, OTPs, banking details, or personal data.",
    ),
    "suspicious": (
        "Suspicious means the URL has warning signs but may not be confirmed phishing.",
        "Users should verify the destination before interacting.",
    ),
    "safe": (
        "Safe means no immediate phishing threat was identified from the available scan context.",
        "Users should still be careful with unexpected or unsolicited links.",
    ),
}

SCAN_TERM_ALIASES = {
    "detection sensitive": "detection sensitivity",
    "detect sensitivity": "detection sensitivity",
    "sensitive": "detection sensitivity",
    "sensitivity": "detection sensitivity",
    "phishing chance": "phishing probability",
    "phishing percentage": "phishing probability",
    "probability": "phishing probability",
    "system verdict": "system detection",
    "machine detection": "system detection",
    "safety verdict": "safety status",
    "final status": "safety status",
    "final verdict": "verdict",
    "url verdict": "url status",
    "attack tag": "mitre att&ck tags",
    "mitre tag": "mitre att&ck tags",
    "mitre mapping": "mitre technique",
    "nist": "nist response",
    "actions": "recommended actions",
    "recommendation": "recommended actions",
}


def _question_asks_term_meaning(question: str) -> bool:
    normalized = question.lower()
    return any(phrase in normalized for phrase in [
        "what does",
        "what is",
        "meaning",
        "mean?",
        "means",
        "explain",
        "define",
        "wha does",
    ])


def _term_explanation_answer(question: str, scan_context: dict) -> str:
    if not _question_asks_term_meaning(question):
        return ""

    normalized = question.lower().replace("attack", "att&ck")
    matched_terms = []
    for term in SCAN_TERM_EXPLANATIONS:
        if re.search(r"\b" + re.escape(term) + r"\b", normalized):
            matched_terms.append(term)

    for alias, term in SCAN_TERM_ALIASES.items():
        if re.search(r"\b" + re.escape(alias) + r"\b", normalized) and term not in matched_terms:
            matched_terms.append(term)

    if not matched_terms:
        return ""

    verdict, confidence, risk, _ = _context_parts(scan_context)
    parts = []
    for term in matched_terms[:2]:
        explanation = SCAN_TERM_EXPLANATIONS[term]
        parts.append((term.title(), f"{explanation[0]} {explanation[1]}"))

    parts.append(("Current scan", f"{verdict}, {risk} risk, {confidence} confidence."))
    return _chat_sections(*parts)


def _question_is_scan_related(question: str) -> bool:
    normalized = question.lower()
    scan_terms = [
        "url",
        "link",
        "scan",
        "result",
        "verdict",
        "status",
        "risk",
        "confidence",
        "score",
        "probability",
        "sensitivity",
        "detection",
        "safe",
        "phishing",
        "suspicious",
        "mitre",
        "t1566",
        "nist",
        "incident",
        "indicator",
        "evidence",
        "clicked",
        "open",
        "access",
        "admin",
        "report",
        "credential",
        "otp",
        "password",
    ]
    return any(term in normalized for term in scan_terms)


def _off_topic_answer() -> str:
    return _chat_sections(
        ("Scope", "I can only help with the current ShieldURL scan result and URL safety."),
        ("Try asking", "Choose a category button for verdict, confidence, risk, indicators, MITRE, NIST, or recommended actions."),
        ("Limit", "I cannot answer unrelated general questions from this assistant.")
    )


def _format_confidence(confidence) -> str:
    try:
        value = float(confidence)
    except (TypeError, ValueError):
        return "unknown"
    if 0 <= value <= 1:
        value *= 100
    rounded = round(value, 2)
    if rounded.is_integer():
        return f"{int(rounded)}%"
    return f"{rounded:.2f}%"


def _display_verdict(status: str, confidence: float) -> str:
    if status.lower() == "phishing" and confidence < 0.70:
        return "Potentially Suspicious"
    return status.replace("_", " ").title()


def _context_parts(scan_context: dict) -> tuple[str, str, str, list[str]]:
    detection = scan_context.get("detection") if isinstance(scan_context, dict) else {}
    if not isinstance(detection, dict):
        detection = {}
    verdict = str(detection.get("display_verdict") or detection.get("final_verdict") or "UNKNOWN").upper()
    confidence = _format_confidence(detection.get("phishing_probability", detection.get("confidence_score", "unknown")))
    risk = str(detection.get("risk_level") or "unknown").lower()
    indicators = scan_context.get("suspicious_indicators") if isinstance(scan_context, dict) else []
    if not isinstance(indicators, list):
        indicators = []
    indicators = [str(item).strip() for item in indicators if str(item).strip()]
    return verdict, confidence, risk, indicators


def _chat_sections(*sections: tuple[str, str]) -> str:
    cleaned = []
    for label, body in sections[:3]:
        label = _redact_for_log(str(label)).strip().rstrip(":")
        body = re.sub(r"\s+", " ", str(body or "")).strip()
        if label and body:
            cleaned.append(f"{label}:\n{body}")
    return "\n\n".join(cleaned)


def _indicator_text(indicators: list[str], fallback: str = "No specific indicators were listed in the scan context.") -> str:
    return ", ".join(indicators[:3]) if indicators else fallback


def _is_potentially_suspicious_context(scan_context: dict) -> bool:
    detection = scan_context.get("detection") if isinstance(scan_context, dict) else {}
    overall = scan_context.get("overall") if isinstance(scan_context, dict) else {}
    text = " ".join(str(item).lower() for item in [
        detection.get("display_verdict") if isinstance(detection, dict) else "",
        overall.get("display_verdict") if isinstance(overall, dict) else "",
        scan_context.get("display_verdict") if isinstance(scan_context, dict) else "",
    ])
    return "potentially suspicious" in text


def _scan_mode(scan_context: dict) -> str:
    verdict, _, risk, _ = _context_parts(scan_context)
    text = f"{verdict} {risk}".lower()
    if _is_potentially_suspicious_context(scan_context) or "suspicious" in text:
        return "suspicious"
    if "phishing" in text or "high" in text:
        return "phishing"
    if "safe" in text or "legitimate" in text or "low" in text:
        return "safe"
    return "unknown"


def _mode_summary(scan_context: dict) -> str:
    verdict, confidence, risk, indicators = _context_parts(scan_context)
    indicator_text = ", ".join(indicators[:3]) if indicators else "none listed in the scan context"
    return f"verdict: {verdict}, risk: {risk}, confidence: {confidence}, indicators: {indicator_text}"


def _risky_open_guidance(scan_context: dict) -> str:
    verdict, confidence, risk, indicators = _context_parts(scan_context)
    mode = _scan_mode(scan_context)

    if mode == "safe":
        return _chat_sections(
            ("Status", f"The scan did not find strong phishing indicators. Current result is {verdict}, {risk} risk, {confidence} confidence."),
            ("Safety advice", "Open it only if you trust the source and expected the link."),
            ("Caution", "Do not enter sensitive data if the page looks unusual or came from an unexpected message.")
        )

    if mode == "suspicious":
        return _chat_sections(
            ("Status", f"This URL is not confirmed safe. Current result is {verdict}, {risk} risk, {confidence} confidence."),
            ("Safety advice", "Avoid opening or interacting with it until IT/security reviews it."),
            ("Do not enter", "Do not submit credentials, OTPs, banking details, or personal data.")
        )

    return _chat_sections(
        ("Status", f"Do not open it. Current result is {verdict}, {risk} risk, {confidence} confidence."),
        ("Evidence", f"Key indicators: {_indicator_text(indicators)}"),
        ("Recommended action", "Report it to IT/security and block it if policy allows.")
    )


def _risky_danger_explanation(scan_context: dict) -> str:
    verdict, confidence, risk, indicators = _context_parts(scan_context)
    mode = _scan_mode(scan_context)
    if indicators:
        indicator_text = ", ".join(indicators[:5])
    else:
        indicator_text = "the current scan context does not list specific indicators"
    if mode == "safe":
        return _chat_sections(
            ("Status", f"This result is {verdict}, with {risk} risk and {confidence} confidence."),
            ("Meaning", "No strong phishing indicators were detected in the current scan."),
            ("Caution", "Still verify the sender and destination before entering sensitive data.")
        )
    if mode == "suspicious":
        return _chat_sections(
            ("Status", f"This URL is {verdict}, with {risk} risk and {confidence} confidence."),
            ("Meaning", f"It has suspicious signals, but the scan does not confirm phishing. Indicators: {indicator_text}."),
            ("Recommended action", "Avoid interaction and ask IT/security to review it before use.")
        )

    return _chat_sections(
        ("Status", f"This URL was classified as {verdict}, with {risk} risk and {confidence} confidence."),
        ("Meaning", f"It may be designed to deceive users or collect sensitive information. Indicators: {indicator_text}."),
        ("Recommended action", "Do not open it. Report it to IT/security for blocking and review.")
    )


def _clicked_guidance(scan_context: dict) -> str:
    verdict, confidence, risk, _ = _context_parts(scan_context)
    mode = _scan_mode(scan_context)
    if mode == "safe":
        return _chat_sections(
            ("Status", "No strong phishing indicators were detected by this scan."),
            ("If clicked", "Verify the page is expected and belongs to the real service."),
            ("Caution", "Do not enter sensitive data if anything looks unusual or unsolicited.")
        )
    if mode == "suspicious":
        return _chat_sections(
            ("Status", f"The URL is potentially suspicious: {verdict}, {risk} risk, {confidence} confidence."),
            ("If clicked", "Stop interacting and do not enter more passwords, OTPs, banking details, or personal data."),
            ("Recommended action", "Report it to IT/security and change credentials if you already entered them.")
        )
    return _chat_sections(
        ("Status", f"Treat this as urgent: {verdict}, {risk} risk, {confidence} confidence."),
        ("If clicked", "Stop interacting and do not enter any more passwords, OTPs, banking details, or personal data."),
        ("Recommended action", "Report it, change credentials if entered, enable MFA, and monitor account logins.")
    )


def _it_admin_guidance(scan_context: dict) -> str:
    verdict, confidence, risk, indicators = _context_parts(scan_context)
    mode = _scan_mode(scan_context)
    indicator_text = ", ".join(indicators[:3]) if indicators else "none listed in the scan context"
    if mode == "safe":
        return _chat_sections(
            ("Admin view", f"Review the scan as {verdict}, {risk} risk, {confidence} confidence."),
            ("Action", "No immediate blocking is required from the current scan alone."),
            ("Follow-up", "Verify source and business context if the URL was unsolicited, then monitor for user reports.")
        )
    if mode == "suspicious":
        return _chat_sections(
            ("Admin view", f"Triage as potentially suspicious: {verdict}, {risk} risk, {confidence} confidence."),
            ("Review focus", f"Check indicators and business context. Indicators: {indicator_text}."),
            ("Action", "Review proxy, DNS, browser, email, and authentication logs if users interacted.")
        )
    return _chat_sections(
        ("Admin view", f"Triage as phishing: {verdict}, {risk} risk, {confidence} confidence."),
        ("Evidence", f"Review indicators and exposure logs. Indicators: {indicator_text}."),
        ("Action", "Block or quarantine the URL, check DNS/proxy/email/browser logs, and document the case.")
    )


def _confidence_explanation(scan_context: dict) -> str:
    verdict, confidence, risk, indicators = _context_parts(scan_context)
    indicator_text = ", ".join(indicators[:3]) if indicators else "no specific indicators listed"
    return _chat_sections(
        ("Confidence", f"The score is {confidence} for the current scan result."),
        ("Meaning", f"It shows how strongly the available URL signals support the {verdict} verdict and {risk} risk level."),
        ("Context", f"Key indicators: {indicator_text}. It is not proof that ShieldURL visited the URL externally.")
    )


def _mitre_explanation(scan_context: dict) -> str:
    verdict, confidence, risk, _ = _context_parts(scan_context)
    return _chat_sections(
        ("Technique", "T1566.002 is MITRE ATT&CK's Spearphishing Link technique."),
        ("Meaning", "It describes links used to lure users to malicious, deceptive, or credential-harvesting pages."),
        ("Current scan", f"The mapped context is {verdict}, {risk} risk, {confidence} confidence; the tag classifies behavior, not confirmed compromise.")
    )


def _indicator_explanation(scan_context: dict) -> str:
    verdict, confidence, risk, indicators = _context_parts(scan_context)
    indicator_text = ", ".join(indicators[:5]) if indicators else "the current scan context does not list specific indicators"
    return _chat_sections(
        ("Signals", f"Detected indicators: {indicator_text}."),
        ("Meaning", f"These signals support the {verdict} verdict with {risk} risk and {confidence} confidence."),
        ("Use", "Use the indicators to decide whether to block, report, or request IT/security review.")
    )


def _verdict_risk_explanation(scan_context: dict) -> str:
    verdict, confidence, risk, indicators = _context_parts(scan_context)
    indicator_text = ", ".join(indicators[:3]) if indicators else "none listed"
    return _chat_sections(
        ("Verdict", f"The current verdict is {verdict}."),
        ("Risk", f"Risk is {risk}, with {confidence} confidence."),
        ("Evidence", f"Key indicators: {indicator_text}. Follow the displayed recommendation before interacting.")
    )


def _phishing_definition() -> str:
    return _chat_sections(
        ("Definition", "Phishing is a deception attempt that tries to steal sensitive information."),
        ("Common signs", "It often uses fake login pages, urgent messages, lookalike domains, or unexpected links."),
        ("Safety advice", "Do not enter passwords, OTPs, banking data, or personal details unless the destination is verified.")
    )


def _scan_context_summary_answer(scan_context: dict) -> str:
    verdict, confidence, risk, indicators = _context_parts(scan_context)
    mode = _scan_mode(scan_context)
    indicator_text = ", ".join(indicators[:3]) if indicators else "none listed in the scan context"
    if mode == "safe":
        return _chat_sections(
            ("Status", f"The scan did not find strong phishing indicators: {verdict}, {risk} risk, {confidence} confidence."),
            ("Meaning", "This is reassuring, but it does not guarantee the link is safe in every context."),
            ("Advice", "Verify the sender and destination before entering sensitive data.")
        )
    if mode == "suspicious":
        return _chat_sections(
            ("Status", f"The URL is potentially suspicious, not confirmed safe: {verdict}, {risk} risk, {confidence} confidence."),
            ("Evidence", f"Key indicators: {indicator_text}."),
            ("Advice", "Avoid interaction until IT/security reviews it.")
        )
    return _chat_sections(
        ("Status", f"I can answer based on this scan: {verdict}, {risk} risk, {confidence} confidence."),
        ("Evidence", f"Key indicators: {indicator_text}."),
        ("Advice", "Do not enter credentials or sensitive data unless the destination is verified.")
    )


def _result_meaning_answer(scan_context: dict) -> str:
    verdict, confidence, risk, _ = _context_parts(scan_context)
    mode = _scan_mode(scan_context)
    if mode == "safe":
        return _chat_sections(
            ("Result", f"ShieldURL classified this URL as {verdict} with {risk} risk."),
            ("What it means", "No strong phishing indicators were found in the current scan."),
            ("User guidance", "You may proceed carefully only if the source and destination are expected.")
        )
    if mode == "suspicious":
        return _chat_sections(
            ("Result", f"ShieldURL marked this URL as {verdict} with {risk} risk."),
            ("What it means", "The URL has warning signs, but the scan does not confirm phishing."),
            ("User guidance", "Avoid interaction until IT/security verifies the link.")
        )
    return _chat_sections(
        ("Result", f"ShieldURL classified this URL as {verdict} with {risk} risk."),
        ("What it means", "The scan result indicates a likely phishing or deceptive link."),
        ("User guidance", "Do not open it or enter information; report it for security review.")
    )


def _flagged_reason_answer(scan_context: dict) -> str:
    verdict, confidence, risk, indicators = _context_parts(scan_context)
    mode = _scan_mode(scan_context)
    indicator_text = _indicator_text(indicators)
    if mode == "safe":
        return _chat_sections(
            ("Detection reason", "The URL was not strongly flagged for phishing in the current scan."),
            ("Signals reviewed", f"ShieldURL reviewed available URL signals and found: {indicator_text}"),
            ("Interpretation", f"The result remained {verdict}, with {confidence} confidence.")
        )
    if mode == "suspicious":
        return _chat_sections(
            ("Detection reason", "ShieldURL found suspicious characteristics that need review."),
            ("Signals", f"Detected or relevant signals: {indicator_text}"),
            ("Why this matters", "Suspicious structure or behavior can be used in deceptive campaigns even when phishing is not confirmed.")
        )
    return _chat_sections(
        ("Detection reason", "ShieldURL detected URL patterns commonly associated with phishing activity."),
        ("Signals", f"Detected or relevant signals: {indicator_text}"),
        ("Why this matters", "These signals contributed to the phishing verdict and urgent response recommendation.")
    )


def _danger_impact_answer(scan_context: dict) -> str:
    verdict, confidence, risk, _ = _context_parts(scan_context)
    mode = _scan_mode(scan_context)
    if mode == "safe":
        return _chat_sections(
            ("Danger level", f"Current danger appears low: {verdict}, {risk} risk, {confidence} confidence."),
            ("Possible impact", "No strong phishing impact is indicated by this scan."),
            ("Caution", "Unexpected links can still be risky if the page later redirects or asks for sensitive data.")
        )
    if mode == "suspicious":
        return _chat_sections(
            ("Danger level", f"Use caution: {verdict}, {risk} risk, {confidence} confidence."),
            ("Possible impact", "Users could be led to a deceptive page or unsafe destination if the URL is malicious."),
            ("Risk control", "Avoid entering credentials or downloading files until review is complete.")
        )
    return _chat_sections(
        ("Danger level", f"High concern: {verdict}, {risk} risk, {confidence} confidence."),
        ("Possible impact", "Users may face credential theft, fake login pages, fraud, or account compromise."),
        ("Organization risk", "If shared broadly, it can expose multiple users and require blocking, reporting, and log review.")
    )


def _safe_reason_answer(scan_context: dict) -> str:
    verdict, confidence, risk, indicators = _context_parts(scan_context)
    mode = _scan_mode(scan_context)
    if mode != "safe":
        return _chat_sections(
            ("Not applicable", "This question is only shown for SAFE scan results."),
            ("Current result", f"The current scan is {verdict}, with {risk} risk and {confidence} confidence."),
            ("Advice", "Use the risk or response categories for this result.")
        )
    return _chat_sections(
        ("Safe reason", "ShieldURL did not find strong phishing indicators in the scanned URL."),
        ("Scan context", f"The verdict is {verdict}, with {risk} risk and {confidence} confidence."),
        ("Still verify", "Users should still confirm the sender, domain, and page content before entering sensitive data.")
    )


def _mitre_tag_meaning_answer(scan_context: dict) -> str:
    verdict, confidence, risk, _ = _context_parts(scan_context)
    return _chat_sections(
        ("Explanation", "MITRE ATT&CK tags are standardized labels for attacker techniques and behaviors."),
        ("Why ShieldURL shows them", "They help analysts understand what kind of threat pattern the URL resembles."),
        ("Scan link", f"For this result, the mapping supports the {verdict} verdict with {risk} risk and {confidence} confidence.")
    )


def _t1566_answer(scan_context: dict) -> str:
    verdict, confidence, risk, _ = _context_parts(scan_context)
    return _chat_sections(
        ("Technique", "T1566.002 means Spearphishing Link."),
        ("How it works", "Attackers use links to bring users to deceptive pages, fake login portals, or credential-harvesting sites."),
        ("Current result", f"This scan is {verdict}, {risk} risk, with {confidence} confidence.")
    )


def _phishing_relation_answer(scan_context: dict) -> str:
    verdict, confidence, risk, indicators = _context_parts(scan_context)
    signal_text = _indicator_text(indicators, "URL-based behavior can still resemble phishing even when detailed indicators are limited.")
    return _chat_sections(
        ("Connection", "Phishing often depends on deceptive links that push users toward fake pages or login prompts."),
        ("Scan signals", f"ShieldURL relates this URL to phishing behavior through signals such as: {signal_text}"),
        ("Why it matters", f"The current result is {verdict}, {risk} risk, {confidence} confidence, so users should avoid trust decisions based only on appearance.")
    )


def _technique_selected_answer(scan_context: dict) -> str:
    verdict, confidence, risk, _ = _context_parts(scan_context)
    return _chat_sections(
        ("Selection reason", "The technique was selected because the scan involves URL-based phishing behavior."),
        ("Important note", "This mapping classifies observed behavior; it does not prove that an account or device was compromised."),
        ("Review context", f"Use it with the verdict: {verdict}, {risk} risk, {confidence} confidence.")
    )


def _credential_theft_answer(scan_context: dict) -> str:
    verdict, confidence, risk, indicators = _context_parts(scan_context)
    mode = _scan_mode(scan_context)
    if mode == "safe":
        return _chat_sections(
            ("Assessment", "This scan did not identify strong credential-theft indicators."),
            ("Still avoid", "Do not enter passwords, OTPs, banking details, or personal data if the page looks unexpected."),
            ("Safer path", "Use the official website or app directly if unsure.")
        )
    if mode == "suspicious":
        return _chat_sections(
            ("Assessment", "Credential theft is possible but not confirmed by this scan."),
            ("Sensitive data", "Avoid entering passwords, OTPs, banking details, or personal data until IT/security reviews it."),
            ("Reason", f"Current result is {verdict}, {risk} risk, {confidence} confidence.")
        )
    return _chat_sections(
        ("Assessment", "Yes, this could be credential theft behavior."),
        ("Target data", "Phishing pages commonly ask for passwords, OTPs, banking details, or login form entries."),
        ("Action", "Do not enter data; reset credentials if anything was submitted.")
    )


def _credential_safety_answer(scan_context: dict) -> str:
    verdict, confidence, risk, _ = _context_parts(scan_context)
    mode = _scan_mode(scan_context)
    if mode == "safe":
        return _chat_sections(
            ("Safety answer", "The scan does not show strong evidence that this URL steals credentials."),
            ("Do not enter", "Avoid typing passwords, OTPs, or banking details if the page was unexpected."),
            ("Safer option", "Open the official website directly instead of trusting a message link.")
        )
    if mode == "suspicious":
        return _chat_sections(
            ("Safety answer", "Credential theft cannot be ruled out for this suspicious URL."),
            ("Do not enter", "Do not type passwords, OTPs, banking details, or recovery codes."),
            ("Safer option", "Use the official site or wait for IT/security review.")
        )
    return _chat_sections(
        ("Safety answer", "Yes, it may try to steal credentials if users interact with it."),
        ("Do not enter", "Do not type passwords, OTPs, banking details, personal data, or recovery codes."),
        ("If already entered", "Reset the affected password, enable MFA, and review recent account logins.")
    )


def _attack_behavior_answer(scan_context: dict) -> str:
    verdict, confidence, risk, indicators = _context_parts(scan_context)
    if indicators:
        behavior = ", ".join(indicators[:4])
    else:
        behavior = "No detailed indicators were provided, but the verdict and confidence still suggest phishing-like URL behavior."
    return _chat_sections(
        ("Observed behavior", behavior),
        ("Interpretation", "The behavior is evaluated as URL-based deception or suspicious link activity."),
        ("Scan result", f"Verdict is {verdict}, {risk} risk, with {confidence} confidence.")
    )


def _severity_answer(scan_context: dict) -> str:
    verdict, confidence, risk, _ = _context_parts(scan_context)
    mode = _scan_mode(scan_context)
    if mode == "safe":
        return _chat_sections(
            ("Seriousness", f"Severity is low: {verdict}, {risk} risk, {confidence} confidence."),
            ("Urgency", "No urgent incident response is required from this scan alone."),
            ("Care", "Users should still verify unexpected links before entering data.")
        )
    if mode == "suspicious":
        return _chat_sections(
            ("Seriousness", f"Severity requires review: {verdict}, {risk} risk, {confidence} confidence."),
            ("Urgency", "Avoid user interaction until the URL is checked by IT/security."),
            ("Priority", "Treat it as a cautious investigation rather than confirmed compromise.")
        )
    return _chat_sections(
        ("Seriousness", f"Severity is high: {verdict}, {risk} risk, {confidence} confidence."),
        ("Urgency", "Act quickly because users may be exposed to phishing or credential theft."),
        ("Priority", "Block, report, and review user exposure as an incident-response priority.")
    )


def _high_risk_meaning_answer(scan_context: dict) -> str:
    verdict, confidence, risk, _ = _context_parts(scan_context)
    return _chat_sections(
        ("Meaning", "High risk means the scan found strong threat signals that deserve fast action."),
        ("Priority", "It should be handled before normal low-risk review work."),
        ("Current result", f"The scan shows {verdict}, {risk} risk, and {confidence} confidence.")
    )


def _organization_impact_answer(scan_context: dict) -> str:
    verdict, confidence, risk, _ = _context_parts(scan_context)
    mode = _scan_mode(scan_context)
    if mode == "safe":
        return _chat_sections(
            ("Organization impact", "Organization-wide impact is unlikely from this scan alone."),
            ("Still monitor", "Unexpected links can still cause support tickets or user confusion."),
            ("Current result", f"{verdict}, {risk} risk, {confidence} confidence.")
        )
    if mode == "suspicious":
        return _chat_sections(
            ("Organization impact", "If shared widely, this URL could create exposure that needs review."),
            ("Possible issues", "Risks include user confusion, credential entry, or escalation into a wider incident."),
            ("Current result", f"{verdict}, {risk} risk, {confidence} confidence.")
        )
    return _chat_sections(
        ("Organization impact", "A phishing URL can affect the organization beyond one user."),
        ("Possible issues", "Impact may include account compromise, data exposure, fraud, productivity disruption, and a wider incident."),
        ("IT priority", "Identify affected users, block the URL, and review relevant logs.")
    )


def _false_positive_answer(scan_context: dict) -> str:
    verdict, confidence, risk, indicators = _context_parts(scan_context)
    mode = _scan_mode(scan_context)
    if mode == "safe":
        return _chat_sections(
            ("Assessment", "This is not a phishing flag, so false positive concern is low."),
            ("Review note", "Still verify the link if it arrived unexpectedly."),
            ("Current result", f"{verdict}, {risk} risk, {confidence} confidence.")
        )
    if mode == "suspicious":
        return _chat_sections(
            ("Assessment", "A false positive is possible because the result is not confirmed phishing."),
            ("Review note", "Check the URL purpose, sender, destination, and any listed indicators."),
            ("Safety", "Avoid interaction until review is complete.")
        )
    return _chat_sections(
        ("Assessment", "False positives are possible, but this should be treated carefully."),
        ("Reason", f"High-risk or high-confidence results carry stronger warning signals: {verdict}, {risk} risk, {confidence} confidence."),
        ("Review note", "Do not interact until IT/security verifies whether it is benign.")
    )


def _click_consequence_answer(scan_context: dict) -> str:
    verdict, confidence, risk, _ = _context_parts(scan_context)
    mode = _scan_mode(scan_context)
    if mode == "safe":
        return _chat_sections(
            ("Likely outcome", "No immediate phishing consequence is indicated by this scan."),
            ("Still possible", "A clicked page could still redirect or ask for sensitive data later."),
            ("Safety advice", "Verify the page before entering information or downloading files.")
        )
    if mode == "suspicious":
        return _chat_sections(
            ("Likely outcome", "Users could land on a deceptive or unsafe destination."),
            ("Possible impact", "They may be prompted for credentials, redirected, or encouraged to download files."),
            ("Safety advice", "Avoid interaction until IT/security reviews the URL.")
        )
    return _chat_sections(
        ("Likely outcome", "Users may be taken to a fake login page or credential-harvesting site."),
        ("Possible impact", "Consequences can include credential entry, redirection, malware download attempts, or account compromise."),
        ("Response", "Close the page, report the URL, and reset credentials if anything was entered.")
    )


def _predefined_question_answer(question: str, scan_context: dict) -> str:
    normalized = question.lower().strip()
    verdict, confidence, risk, indicators = _context_parts(scan_context)
    mode = _scan_mode(scan_context)
    indicator_text = ", ".join(indicators[:3]) if indicators else "none listed in the scan context"

    if normalized == "what does this result mean?":
        return _result_meaning_answer(scan_context)

    if normalized == "why was this url flagged?":
        return _flagged_reason_answer(scan_context)

    if normalized == "is this url dangerous?":
        return _danger_impact_answer(scan_context)

    if normalized == "why is this url considered safe?":
        return _safe_reason_answer(scan_context)

    if normalized == "what indicators were detected?":
        return _indicator_explanation(scan_context)

    if normalized == "what should i do now?":
        if mode == "safe":
            return _chat_sections(
                ("Action", "You can treat the scan as low concern, but stay cautious."),
                ("Verify", "Check the sender and destination before entering sensitive data."),
                ("Report", "Report the link if it was unsolicited or behaves unexpectedly.")
            )
        if mode == "suspicious":
            return _chat_sections(
                ("Action", "Avoid opening or interacting with the URL for now."),
                ("Do not enter", "Do not submit passwords, OTPs, banking details, or personal data."),
                ("Review", "Send the scan result to IT/security and use a verified official website instead.")
            )
        return _chat_sections(
            ("Action", "Do not open or interact with the URL."),
            ("Incident response", "Report it to IT/security immediately and block the URL or domain if policy allows."),
            ("If exposed", "Change passwords if credentials were entered and monitor accounts for unusual logins.")
        )

    if normalized == "what should i avoid doing?":
        if mode == "safe":
            return _chat_sections(
                ("Avoid", "Do not ignore context just because the scan is safe."),
                ("Sensitive data", "Avoid entering credentials if the sender, domain, or page content looks unexpected."),
                ("Safer habit", "Use bookmarks or official apps for important services.")
            )
        if mode == "suspicious":
            return _chat_sections(
                ("Avoid", "Do not open, click through, or submit information until review is complete."),
                ("Sensitive data", "Avoid passwords, OTPs, banking details, and file downloads."),
                ("Safer path", "Use the official website directly or ask IT/security to verify the URL.")
            )
        return _chat_sections(
            ("Avoid", "Do not open the URL or continue interacting with the page."),
            ("Sensitive data", "Do not enter passwords, OTPs, banking details, or personal information."),
            ("Device safety", "Avoid downloads and report any interaction immediately.")
        )

    if normalized == "should i block this url?":
        if mode == "safe":
            return _chat_sections(("Decision", "Blocking is not required based on this scan alone."), ("Check", "Verify the source if the link was unexpected."), ("Monitor", "Watch for user reports or repeated submissions."))
        if mode == "suspicious":
            return _chat_sections(("Decision", "Consider temporary blocking or restricted access during review."), ("Reason", "It is not confirmed safe, so avoid user interaction."), ("Next step", "Let IT/security confirm before permanent action."))
        return _chat_sections(("Decision", "Yes, block the URL or domain if policy allows."), ("Containment", "Remove it from messages or tickets where possible."), ("Review", "Check proxy, DNS, email, and browser logs."))

    if normalized == "should i reset my password?":
        if mode == "safe":
            return _chat_sections(("Decision", "A reset is not required from this scan alone."), ("When to reset", "Reset only if you entered credentials on a page you do not trust."), ("Protection", "Enable MFA and monitor login activity."))
        if mode == "suspicious":
            return _chat_sections(("Decision", "Reset passwords if credentials were entered."), ("Protection", "Enable MFA and review recent logins."), ("Report", "Report the interaction to IT/security."))
        return _chat_sections(("Decision", "Reset passwords immediately if credentials were entered."), ("Protection", "Enable MFA and revoke suspicious sessions."), ("Review", "Check account login history."))

    if normalized == "should i report this incident?":
        if mode == "safe":
            return _chat_sections(("Decision", "Reporting is optional unless the link was unsolicited or suspicious in context."), ("Record", "Keep the scan result for reference."), ("Escalate", "Report repeated or unexpected links."))
        if mode == "suspicious":
            return _chat_sections(("Decision", "Yes, report it for IT/security review."), ("Include", "Provide the URL, scan result, and how users received it."), ("Until reviewed", "Avoid interaction until reviewed."))
        return _chat_sections(("Decision", "Yes, report it as a phishing incident."), ("Include", "Provide the URL, scan result, sender, timestamp, and affected users."), ("Preserve", "Keep related email, browser, proxy, and DNS evidence."))

    if normalized == "is device isolation necessary?":
        if mode == "safe":
            return _chat_sections(("Decision", "Device isolation is not necessary from this scan alone."), ("Investigate if", "Check further only if the user downloaded files or saw unusual behavior."), ("Monitoring", "Continue normal monitoring."))
        if mode == "suspicious":
            return _chat_sections(("Decision", "Isolation is usually not required unless malware, downloads, or compromise signs appear."), ("Review first", "Check endpoint and browser activity."), ("Escalate", "Escalate if suspicious behavior is found."))
        return _chat_sections(("Decision", "Consider isolation if files were downloaded, credentials were entered, or the device behaves abnormally."), ("Review", "Check endpoint alerts and browser history."), ("Escalate", "Escalate to IT/security."))

    if normalized == "how severe is this threat?":
        return _severity_answer(scan_context)

    if normalized == "what does high risk mean?":
        return _high_risk_meaning_answer(scan_context)

    if normalized == "can this affect the organization?":
        return _organization_impact_answer(scan_context)

    if normalized == "what happens if users click this url?":
        return _click_consequence_answer(scan_context)

    if normalized == "is this likely a false positive?":
        return _false_positive_answer(scan_context)

    if normalized == "is this credential theft?":
        return _credential_theft_answer(scan_context)

    if normalized == "can this steal credentials?":
        return _credential_safety_answer(scan_context)

    if normalized == "can this install malware?":
        if mode == "safe":
            return _chat_sections(("Assessment", "The scan does not show malware installation evidence."), ("Caution", "Avoid downloads from unexpected pages."), ("Report", "Report unusual prompts or file downloads."))
        if mode == "suspicious":
            return _chat_sections(("Assessment", "Malware installation is not confirmed, but the URL needs caution."), ("Avoid", "Do not download files from the page."), ("Review", "IT should review if files were downloaded."))
        return _chat_sections(("Assessment", "This scan indicates phishing risk, not confirmed malware installation."), ("Avoid", "Close the page and avoid downloads."), ("Escalate", "Investigate or isolate if files were downloaded."))

    if normalized == "what should i tell employees?":
        if mode == "safe":
            return _chat_sections(("Message", "Tell employees no strong phishing indicators were detected."), ("Reminder", "Ask them to verify unexpected links before entering data."), ("Report", "Ask them to report anything unusual."))
        if mode == "suspicious":
            return _chat_sections(("Message", "Tell employees not to open or interact with the URL until reviewed."), ("Avoid", "Ask them not to enter credentials or OTPs."), ("Alternative", "Provide the official verified link if needed."))
        return _chat_sections(("Message", "Tell employees not to open the URL."), ("Report", "Ask them to report any interaction immediately."), ("If exposed", "Affected users should change passwords if they entered credentials."))

    if normalized == "what is shieldurl?":
        return _chat_sections(("Purpose", "ShieldURL is a URL safety checker for phishing and suspicious links."), ("How it helps", "It combines URL analysis, ML detection, and security guidance."), ("Use", "Run a scan, review the verdict, then follow the recommended action."))

    if normalized == "how does shieldurl work?":
        return _chat_sections(("Scan", "Paste a URL and ShieldURL analyzes URL patterns and extracted security features."), ("Result", "It shows a verdict, risk level, confidence score, MITRE mapping, and recommended actions."), ("Assistant", "The assistant explains the result but does not change the scan decision."))

    if normalized == "how accurate is the detection?":
        return _chat_sections(("Accuracy", "Detection accuracy depends on the URL signals available at scan time."), ("Current scan", f"This scan shows {verdict}, {risk} risk, {confidence} confidence."), ("Best use", "Use the result with user context and IT/security review for important decisions."))

    if normalized == "what does this mitre tag mean?":
        return _mitre_tag_meaning_answer(scan_context)

    if normalized == "what is t1566.002?":
        return _t1566_answer(scan_context)

    if normalized == "how is this related to phishing?":
        return _phishing_relation_answer(scan_context)

    if normalized == "why was this attack technique selected?":
        return _technique_selected_answer(scan_context)

    if normalized == "what attack behavior was detected?":
        return _attack_behavior_answer(scan_context)

    return ""


def _fast_chat_answer(question: str, scan_context: dict) -> str:
    predefined_answer = _predefined_question_answer(question, scan_context)
    if predefined_answer:
        return predefined_answer
    term_answer = _term_explanation_answer(question, scan_context)
    if term_answer:
        return term_answer
    if _question_asks_why_dangerous(question):
        return _risky_danger_explanation(scan_context)
    if _question_asks_clicked_advice(question):
        return _clicked_guidance(scan_context)
    if _question_asks_it_admin(question):
        return _it_admin_guidance(scan_context)
    if _question_asks_confidence(question):
        return _confidence_explanation(scan_context)
    if _question_asks_to_open(question):
        return _risky_open_guidance(scan_context)
    if _question_asks_mitre(question):
        return _mitre_explanation(scan_context)
    if _question_asks_indicators(question):
        return _indicator_explanation(scan_context)
    if _question_asks_verdict_or_risk(question):
        return _verdict_risk_explanation(scan_context)
    if _question_asks_phishing_definition(question):
        return _phishing_definition()
    return ""


def _answer_missing_core_context(answer: str, scan_context: dict) -> bool:
    verdict, confidence, risk, indicators = _context_parts(scan_context)
    normalized = answer.lower()
    if verdict.lower() not in normalized:
        return True
    if confidence != "unknown" and confidence.lower() not in normalized and str(confidence).replace("%", "") not in normalized:
        return True
    if risk != "unknown" and risk.lower() not in normalized:
        return True
    if indicators and not any(indicator.lower() in normalized for indicator in indicators[:3]):
        return True
    return False


@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_path": MODEL_PATH,
        "scan_flow": "app.scan_url.run_scan",
    }


@app.post("/scan")
def scan(req: ScanRequest):
    try:
        logger.info("scan request received url=%s clicked=%s", req.url, req.clicked)
        scan_result = run_scan(req.url, req.clicked, req.generate_llm)
        logger.info("detection finished url=%s timing=%s", req.url, scan_result.get("timing", {}))
        detection = scan_result.get("detection", {})
        llm_report = scan_result.get("llm_report", {})
        if not isinstance(llm_report, dict):
            llm_report = {
                "generated_by": "fallback",
                "error": "Invalid LLM report object",
            }
        logger.info(
            "llm stage finished url=%s generated_by=%s error=%s",
            req.url,
            llm_report.get("generated_by", ""),
            llm_report.get("error", ""),
        )

        if scan_result.get("error"):
            logger.error("run_scan error for %s\n%s", req.url, scan_result.get("traceback", scan_result["error"]))
            return _json_response({
                "success": bool(detection),
                "url": req.url,
                "clicked": req.clicked,
                "ml": {
                    "status": "UNKNOWN",
                    "raw_label": None,
                    "phishing_probability": None,
                    "confidence_score": float(detection.get("confidence_score", 0) or 0),
                    "risk_level": str(detection.get("risk_level", "UNKNOWN")).upper(),
                    "features_used": list((detection.get("features") or {}).keys()),
                    "features": detection.get("features", {}),
                },
                "heuristics": {
                    "triggered": bool(detection.get("heuristic_reasons")),
                    "reasons": detection.get("heuristic_reasons", []),
                    "adjusted_status": str(detection.get("final_verdict", "UNKNOWN")).upper(),
                },
                "overall": {
                    "status": str(detection.get("final_verdict", "UNKNOWN")).upper(),
                    "verdict": "UNKNOWN",
                    "risk_level": str(detection.get("risk_level", "UNKNOWN")).upper(),
                    "source": "scan_url_fallback",
                },
                "llm": llm_report if llm_report else fallback_llm_report({"url": req.url, "clicked": req.clicked, "detection": detection}, scan_result["error"]),
                "llm_report": llm_report if llm_report else fallback_llm_report({"url": req.url, "clicked": req.clicked, "detection": detection}, scan_result["error"]),
                "timing": scan_result.get("timing", {}),
                "message": scan_result["error"],
                "debug": {
                    "traceback": scan_result.get("traceback", ""),
                },
            })

        final_status = str(detection.get("final_verdict", "safe"))
        confidence = float(detection.get("confidence_score", 0))
        phishing_probability = float(detection.get("phishing_probability", confidence) or 0)
        lexical_threshold = float(detection.get("lexical_threshold", 0.5) or 0.5)
        display_verdict = str(detection.get("display_verdict") or _display_verdict(final_status, confidence))
        ml_status = "PHISHING" if final_status == "phishing" else "LEGITIMATE"
        risk_level = str(detection.get("risk_level", "low")).upper()
        heuristic_reasons = detection.get("heuristic_reasons", [])
        model_policy = str(
            detection.get("model_policy")
            or "The system uses advanced URL detection analysis to identify suspicious website patterns."
        )

        return _json_response({
            "success": True,
            "url": req.url,
            "clicked": req.clicked,
            "detection": detection,
            "ml": {
                "status": ml_status,
                "raw_label": 1 if final_status == "phishing" else 0,
                "phishing_probability": phishing_probability,
                "confidence_score": confidence,
                "selected_threshold": lexical_threshold,
                "model_policy": model_policy,
                "risk_level": risk_level,
                "features_used": list((detection.get("features") or {}).keys()),
                "features": detection.get("features", {}),
            },
            "heuristics": {
                "triggered": bool(heuristic_reasons),
                "reasons": heuristic_reasons,
                "adjusted_status": final_status.upper(),
            },
            "overall": {
                "status": final_status.upper(),
                "verdict": "LIKELY_PHISHING" if final_status == "phishing" else "LIKELY_LEGITIMATE",
                "display_verdict": display_verdict,
                "risk_level": risk_level,
                "source": "scan_url",
                "model_policy": model_policy,
            },
            "llm": llm_report if llm_report else fallback_llm_report({"url": req.url, "clicked": req.clicked, "detection": detection}, "LLM timeout or unavailable"),
            "llm_report": llm_report if llm_report else fallback_llm_report({"url": req.url, "clicked": req.clicked, "detection": detection}, "LLM timeout or unavailable"),
            "timing": scan_result.get("timing", {}),
        })
    except Exception as exc:
        tb = traceback.format_exc()
        logger.exception("Unhandled /scan failure for %s", req.url)
        return _json_response({
            "success": False,
            "url": req.url,
            "clicked": req.clicked,
            "message": str(exc),
            "llm": fallback_llm_report({"url": req.url, "clicked": req.clicked}, str(exc)),
            "llm_report": fallback_llm_report({"url": req.url, "clicked": req.clicked}, str(exc)),
            "timing": {},
            "debug": {
                "traceback": tb,
            },
        })


@app.post("/llm_report")
def llm_report(req: LLMReportRequest):
    started = time.perf_counter()
    fallback_used = False
    try:
        if os.environ.get("SKIP_LLM", "0") == "1":
            fallback_used = True
            report = fallback_llm_report({
                "url": req.url,
                "clicked": req.clicked,
                "detection": {
                    "display_verdict": req.verdict,
                    "final_verdict": req.verdict,
                    "confidence_score": req.confidence,
                    "risk_level": req.risk,
                },
            }, "LLM generation skipped via SKIP_LLM")
        else:
            report = generate_ir_report({
                "url": req.url,
                "verdict": req.verdict,
                "confidence": req.confidence,
                "risk": req.risk,
            })
            fallback_used = bool(report.get("error") or report.get("parse_error"))

        llm_seconds = round(time.perf_counter() - started, 3)
        logger.info(
            "llm_report finished url=%s llm_seconds=%s cache_used=false fallback_used=%s",
            req.url,
            llm_seconds,
            fallback_used,
        )
        return _json_response({
            "success": True,
            "llm_report": report,
            "llm": report,
            "timing": {
                "detection_seconds": 0,
                "llm_seconds": llm_seconds,
                "total_seconds": llm_seconds,
                "cache_used": False,
                "fallback_used": fallback_used,
            },
        })
    except Exception as exc:
        llm_seconds = round(time.perf_counter() - started, 3)
        logger.warning("llm_report fallback url=%s error=%s", req.url, exc)
        report = fallback_llm_report({
            "url": req.url,
            "clicked": req.clicked,
            "detection": {
                "display_verdict": req.verdict,
                "final_verdict": req.verdict,
                "confidence_score": req.confidence,
                "risk_level": req.risk,
            },
        }, str(exc))
        return _json_response({
            "success": True,
            "llm_report": report,
            "llm": report,
            "timing": {
                "detection_seconds": 0,
                "llm_seconds": llm_seconds,
                "total_seconds": llm_seconds,
                "cache_used": False,
                "fallback_used": True,
            },
        })


@app.post("/chat")
def chat(req: ChatRequest, request: Request):
    client_host = request.client.host if request.client else "unknown"
    rate_key = f"{client_host}:{req.scan_id or 'no-scan'}"
    if _rate_limited(rate_key):
        return _json_response({
            "answer": "Too many assistant requests. Please wait a moment and try again.",
            "used_scan_context": True,
            "safety_notice": "Detection result was not modified by the LLM.",
        }, status_code=429)

    started = time.perf_counter()
    status = "ok"
    try:
        scan_context = req.scan_context
        if not _valid_scan_context(scan_context):
            scan_context = {
                "checked_url": "",
                "detection": {
                    "final_verdict": "general_question",
                    "risk_level": "unknown",
                    "confidence_score": "",
                },
                "assistant_scope": "General ShieldURL and cybersecurity guidance. Do not claim a URL was scanned unless scan context is provided.",
            }

        answer = _fast_chat_answer(req.message, scan_context)
        if answer:
            status = "fast_answer"
        elif _chat_context_is_risky(scan_context):
            if _question_is_scan_related(req.message):
                answer = _scan_context_summary_answer(scan_context)
                status = "fast_answer"
            else:
                answer = _off_topic_answer()
                status = "off_topic"
        else:
            if not _question_is_scan_related(req.message):
                answer = _off_topic_answer()
                status = "off_topic"
            elif len(req.message.split()) > 14:
                answer = _scan_context_summary_answer(scan_context)
                status = "fast_answer"
            else:
                answer = generate_chat_answer(req.message, scan_context, req.assistant_response_style, req.conversation)
            if (
                _answer_has_placeholder_text(answer)
                or _answer_refuses_help(answer)
            ):
                raise ValueError("LLM returned an invalid assistant answer")

        if not answer:
            raise ValueError("LLM returned an empty answer")

        return _json_response({
            "answer": answer,
            "used_scan_context": True,
            "safety_notice": "Detection result was not modified by the LLM.",
        })
    except Exception as exc:
        status = "fallback"
        logger.warning("chat fallback scan_id=%s error=%s", req.scan_id, exc)
        return _json_response({
            "answer": CHAT_FALLBACK_ANSWER,
            "used_scan_context": True,
            "safety_notice": "Detection result was not modified by the LLM.",
        })
    finally:
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        logger.info(
            "chat request timestamp=%s scan_id=%s status=%s latency_ms=%s question=%s",
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            req.scan_id,
            status,
            latency_ms,
            _redact_for_log(req.message),
        )
