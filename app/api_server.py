import logging
import re
import time
import traceback
from collections import defaultdict, deque
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator

try:
    from .features import MODEL_PATH
    from .scan_url import run_scan
    from .llm_service import fallback_llm_report
    from .llm.chain import generate_chat_answer
except ImportError:
    from features import MODEL_PATH
    from scan_url import run_scan
    from llm_service import fallback_llm_report
    from llm.chain import generate_chat_answer

app = FastAPI(title="ShieldURL API", version="1.0")
logger = logging.getLogger("shieldurl.api")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

CHAT_RATE_LIMIT = 12
CHAT_RATE_WINDOW_SECONDS = 60
_chat_requests: dict[str, deque[float]] = defaultdict(deque)
CHAT_FALLBACK_ANSWER = (
    "The assistant is temporarily unavailable, but the scan result remains valid. "
    "Please follow the recommended actions."
)
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


class ChatRequest(BaseModel):
    scan_id: Optional[str] = None
    user_question: str = Field(..., max_length=500)
    assistant_response_style: str = Field(default="simple")
    scan_context: dict = Field(default_factory=dict)

    @validator("user_question")
    def validate_user_question(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("user_question must be a string")
        value = value.strip()
        if not value:
            raise ValueError("user_question cannot be empty")
        if len(value) > 500:
            raise ValueError("user_question must be 500 characters or fewer")
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
    return any(phrase in normalized for phrase in ["can i open", "should i open", "safe to open", "can i visit", "should i visit"])


def _question_asks_why_dangerous(question: str) -> bool:
    normalized = question.lower()
    return any(phrase in normalized for phrase in ["why is", "why dangerous", "why is this url dangerous", "why is this url phishing", "why phishing"])


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


def _context_parts(scan_context: dict) -> tuple[str, str, str, list[str]]:
    detection = scan_context.get("detection") if isinstance(scan_context, dict) else {}
    if not isinstance(detection, dict):
        detection = {}
    verdict = str(detection.get("final_verdict") or "UNKNOWN").upper()
    confidence = _format_confidence(detection.get("confidence_score", "unknown"))
    risk = str(detection.get("risk_level") or "unknown").lower()
    indicators = scan_context.get("suspicious_indicators") if isinstance(scan_context, dict) else []
    if not isinstance(indicators, list):
        indicators = []
    indicators = [str(item).strip() for item in indicators if str(item).strip()]
    return verdict, confidence, risk, indicators


def _risky_open_guidance(scan_context: dict) -> str:
    verdict, confidence, risk, indicators = _context_parts(scan_context)
    indicator_text = ""
    if indicators:
        indicator_text = " The scan context lists suspicious indicators including " + ", ".join(indicators[:3]) + "."

    return (
        f"No. Based on the supplied scan context, the authoritative verdict is {verdict} with {risk} risk "
        f"and {confidence} confidence.{indicator_text} Do not open the URL or enter credentials, OTP, banking details, "
        "or personal data. Report it to IT/security, block the URL or domain where possible, and review relevant browser, DNS, proxy, or email logs."
    )


def _risky_danger_explanation(scan_context: dict) -> str:
    verdict, confidence, risk, indicators = _context_parts(scan_context)
    if indicators:
        indicator_text = ", ".join(indicators[:5])
    else:
        indicator_text = "the current scan context does not list specific indicators"
    return (
        f"Based on the ShieldURL scan result, this URL was classified as {verdict} with {confidence} confidence and {risk} risk. "
        f"The scan context lists suspicious indicators such as {indicator_text}. "
        "If accessed, this URL may lead to credential harvesting, fake login pages, OTP theft, session hijacking, unauthorized account access, or financial fraud. "
        "Do not open the URL or enter login credentials, OTP, banking details, or personal information."
    )


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
        scan_result = run_scan(req.url, req.clicked)
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
        ml_status = "PHISHING" if final_status == "phishing" else "LEGITIMATE"
        risk_level = str(detection.get("risk_level", "low")).upper()
        heuristic_reasons = detection.get("heuristic_reasons", [])

        return _json_response({
            "success": True,
            "url": req.url,
            "clicked": req.clicked,
            "detection": detection,
            "ml": {
                "status": ml_status,
                "raw_label": 1 if final_status == "phishing" else 0,
                "phishing_probability": confidence if final_status == "phishing" else None,
                "confidence_score": confidence,
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
                "risk_level": risk_level,
                "source": "scan_url",
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
            return _json_response({
                "answer": "Please scan a URL first before using the assistant.",
                "message": "Please scan a URL first before using the assistant.",
                "used_scan_context": False,
                "safety_notice": "Detection result was not modified by the LLM.",
            }, status_code=400)

        answer = generate_chat_answer(req.user_question, scan_context, req.assistant_response_style)
        if _chat_context_is_risky(scan_context):
            if _question_asks_why_dangerous(req.user_question):
                answer = _risky_danger_explanation(scan_context)
                status = "guardrail_replaced"
            elif (
                _answer_has_placeholder_text(answer)
                or _answer_softens_risky_verdict(answer)
                or _answer_refuses_help(answer)
                or _question_asks_to_open(req.user_question)
            ):
                answer = _risky_open_guidance(scan_context)
                status = "guardrail_replaced"

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
            _redact_for_log(req.user_question),
        )
