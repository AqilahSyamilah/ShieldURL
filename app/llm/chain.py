from langchain_ollama import OllamaLLM
from langchain_core.output_parsers import JsonOutputParser
import os
from .prompts import chat_prompt, incident_prompt


def _chat_timeout_seconds() -> int:
    raw_timeout = os.environ.get("CHAT_TIMEOUT") or os.environ.get("CHAT_LLM_TIMEOUT_SECONDS")
    if not raw_timeout:
        return 60
    try:
        timeout = int(raw_timeout)
    except ValueError:
        return 60
    return max(1, timeout)


CHAT_LLM_TIMEOUT_SECONDS = _chat_timeout_seconds()

OLLAMA_OPTIONS = {
    "num_ctx": 2048,
    "num_predict": 350,
    "temperature": 0.2,
    "top_p": 0.8,
    "repeat_penalty": 1.1,
    "num_thread": os.cpu_count() or 4,
}

CHAT_OLLAMA_OPTIONS = {
    "num_ctx": 1024,
    "num_predict": 96,
    "temperature": 0.2,
    "top_p": 0.8,
    "repeat_penalty": 1.1,
    "num_thread": os.cpu_count() or 4,
    "keep_alive": "10m",
    "sync_client_kwargs": {"timeout": CHAT_LLM_TIMEOUT_SECONDS},
    "async_client_kwargs": {"timeout": CHAT_LLM_TIMEOUT_SECONDS},
}

llm = OllamaLLM(model="llama3.2:latest", **OLLAMA_OPTIONS)
chat_llm = OllamaLLM(model="llama3.2:latest", **CHAT_OLLAMA_OPTIONS)
parser = JsonOutputParser()

raw_chain = incident_prompt | llm
chain = raw_chain | parser
chat_chain = chat_prompt | chat_llm


def _normalise_report(report, verdict=""):
    if not isinstance(report, dict):
        raise ValueError("LLM response is not a JSON object")

    containment_actions = _drop_placeholder_items(_safe_string_list(report.get("containment_actions")))
    eradication_actions = _drop_placeholder_items(_safe_string_list(report.get("eradication_recovery_actions")))
    post_incident_actions = _drop_placeholder_items(_safe_string_list(report.get("post_incident_recommendations")))

    verdict_text = str(verdict or "").lower()
    safe = "safe" in verdict_text or "legitimate" in verdict_text
    potentially_suspicious = "potentially suspicious" in verdict_text or "suspicious" in verdict_text
    if safe:
        containment_actions = []
        eradication_actions = []
        post_incident_actions = [
            "No immediate action is required.",
            "Continue safe browsing practices.",
        ]
    elif potentially_suspicious:
        containment_actions = _drop_strong_blocking_items(containment_actions)
        eradication_actions = _drop_strong_blocking_items(eradication_actions)
        post_incident_actions = _drop_strong_blocking_items(post_incident_actions)
    default_containment = [] if safe else ([
        "Review the URL carefully before allowing user interaction.",
        "Verify the destination and source before users enter credentials or sensitive information.",
    ] if potentially_suspicious else [
        "Block the URL and domain across DNS filtering, proxy, firewall, and email gateway.",
        "Review proxy, DNS, browser, and email logs to identify affected users.",
    ])
    default_recovery = [] if safe else ([
        "Check whether users interacted with the URL if it was shared internally.",
        "Escalate for blocking only if review confirms malicious behavior or organization policy requires it.",
    ] if potentially_suspicious else [
        "Reset credentials immediately if users entered login information.",
        "Enable MFA on affected accounts and review login history.",
    ])
    default_recommendations = [
        "No immediate action is required.",
        "Continue safe browsing practices.",
    ] if safe else ([
        "Document the suspicious indicators and review outcome.",
        "Remind users to verify unexpected links before entering credentials or sensitive information.",
    ] if potentially_suspicious else [
        "Document the incident and preserve relevant scan, email, DNS, proxy, and endpoint evidence.",
        "Conduct phishing awareness training if users were affected.",
    ])

    mitre_mapping = [] if safe else _safe_string_list(report.get("mitre_attack_mapping"))
    if potentially_suspicious and not mitre_mapping:
        mitre_mapping = ["Potentially Related: T1566.002 - Spearphishing Link"]
    if not safe and not potentially_suspicious and not mitre_mapping:
        mitre_mapping = ["T1566.002 - Spearphishing Link"]

    return {
        "incident_summary": str(report.get("incident_summary", "")).strip(),
        "containment_actions": containment_actions or default_containment,
        "mitre_attack_mapping": mitre_mapping,
        "detection_analysis": _safe_string_list(report.get("detection_analysis")),
        "eradication_recovery_actions": eradication_actions or default_recovery,
        "post_incident_recommendations": post_incident_actions or default_recommendations,
        "user_advisory": str(report.get("user_advisory", "")).strip(),
    }


def _safe_string_list(value):
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _supported_mitre_mapping(verdict: str, report_mapping: list[str], page_indicators: dict) -> list[str]:
    verdict_text = str(verdict or "").lower()
    if "safe" in verdict_text or "legitimate" in verdict_text:
        return []

    mappings = list(report_mapping)
    lowered = [str(item).lower() for item in mappings]
    suspicious = "suspicious" in verdict_text and "phishing" not in verdict_text
    baseline = (
        "Potentially Related: T1566.002 - Spearphishing Link"
        if suspicious
        else "T1566.002 - Spearphishing Link"
    )
    if not any("t1566.002" in item for item in lowered):
        mappings.insert(0, baseline)

    if not isinstance(page_indicators, dict):
        return mappings

    if page_indicators.get("has_password_field") or page_indicators.get("has_email_field"):
        context = (
            "Potential / LLM-assisted inference: Credential theft context supported by login/email/password form indicators."
        )
        if context.lower() not in [item.lower() for item in mappings]:
            mappings.append(context)

    if page_indicators.get("has_download_link") or page_indicators.get("suspicious_file_extensions"):
        context = (
            "Potential / LLM-assisted inference: T1204.002 - Malicious File, supported by suspicious downloadable file indicators."
        )
        if context.lower() not in [item.lower() for item in mappings]:
            mappings.append(context)

    redirect_count = page_indicators.get("redirect_count")
    try:
        redirected = int(redirect_count or 0) > 0
    except (TypeError, ValueError):
        redirected = False
    if redirected:
        context = "Supporting evidence: page request followed HTTP redirection before landing."
        if context.lower() not in [item.lower() for item in mappings]:
            mappings.append(context)

    return mappings[:4]


def _page_indicator_detection_analysis(page_indicators: dict) -> list[str]:
    if not isinstance(page_indicators, dict):
        return []

    analysis = []
    if page_indicators.get("has_password_field"):
        analysis.append("Safe static HTML analysis found a password input field.")
    if page_indicators.get("has_email_field"):
        analysis.append("Safe static HTML analysis found an email input field.")
    if page_indicators.get("has_form"):
        analysis.append("Safe static HTML analysis found at least one form on the page.")
    if page_indicators.get("has_login_keywords"):
        analysis.append("Login/account keywords were present in the page text.")
    if page_indicators.get("has_bank_or_payment_keywords"):
        analysis.append("Banking or payment keywords were present in the page text.")
    if page_indicators.get("external_form_action"):
        analysis.append("A form submits to an external host.")
    if page_indicators.get("has_download_link"):
        extensions = ", ".join(page_indicators.get("suspicious_file_extensions") or [])
        analysis.append(f"Suspicious download indicators were present{': ' + extensions if extensions else ''}.")

    summary = page_indicators.get("indicators_summary")
    if isinstance(summary, list):
        cleaned = [str(item).strip() for item in summary if str(item).strip()]
        if cleaned:
            analysis.extend(cleaned)

    deduped = []
    seen = set()
    for item in analysis:
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped[:6]


def _ensure_page_indicator_references(report: dict, page_indicators: dict) -> dict:
    page_analysis = _page_indicator_detection_analysis(page_indicators)
    if not page_analysis:
        return report

    existing_analysis = _safe_string_list(report.get("detection_analysis"))
    merged = []
    seen = set()
    for item in [*existing_analysis, *page_analysis]:
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
    report["detection_analysis"] = merged[:6]

    summary = str(report.get("incident_summary", "")).strip()
    if not any(term in summary.lower() for term in ["password", "login", "email", "bank", "payment", "redirect", "download"]):
        report["incident_summary"] = (
            summary + " " if summary else ""
        ) + "Static page indicators also support the assessment: " + " ".join(page_analysis[:2])

    return report


def _drop_placeholder_items(values):
    placeholder_terms = [
        "action 1",
        "action 2",
        "recommendation 1",
        "recommendation 2",
        "practical containment step",
        "practical investigation step",
        "such as",
        "placeholder",
        "example",
    ]
    cleaned = []
    for value in values:
        lowered = value.lower()
        if any(term in lowered for term in placeholder_terms):
            continue
        cleaned.append(value)
    return cleaned


def _drop_strong_blocking_items(values):
    blocked_terms = [
        "block the url",
        "block the domain",
        "quarantine the url",
        "confirmed phishing",
        "avoid this link",
    ]
    cleaned = []
    for value in values:
        lowered = value.lower()
        if any(term in lowered for term in blocked_terms):
            continue
        cleaned.append(value)
    return cleaned


def _inputs(scan_result):
    page_indicators = scan_result.get("page_indicators") or {}
    lexical_indicators = scan_result.get("lexical_indicators") or {}
    return {
        "url": scan_result["url"],
        "verdict": scan_result["verdict"],
        "confidence": scan_result["confidence"],
        "risk": scan_result["risk"],
        "lexical_indicators": lexical_indicators,
        "page_indicators": page_indicators,
        "format_instructions": parser.get_format_instructions(),
    }


def generate_ir_report(scan_result):
    prompt_inputs = _inputs(scan_result)
    raw_report = raw_chain.invoke(prompt_inputs)

    try:
        report = _normalise_report(parser.parse(raw_report), scan_result.get("verdict", ""))
        report = _ensure_page_indicator_references(report, scan_result.get("page_indicators") or {})
        report["mitre_attack_mapping"] = _supported_mitre_mapping(
            scan_result.get("verdict", ""),
            report.get("mitre_attack_mapping", []),
            scan_result.get("page_indicators") or {},
        )
        return report
    except Exception as parse_error:
        return {
            "incident_summary": raw_report,
            "containment_actions": [],
            "mitre_attack_mapping": [],
            "detection_analysis": [],
            "user_advisory": "",
            "raw_report": raw_report,
            "parse_error": str(parse_error),
        }


def _compact_chat_context(scan_context):
    if not isinstance(scan_context, dict):
        return {}

    detection = scan_context.get("detection") if isinstance(scan_context.get("detection"), dict) else {}
    nist_actions = scan_context.get("nist_actions") if isinstance(scan_context.get("nist_actions"), dict) else {}

    indicators = scan_context.get("suspicious_indicators", [])
    if not isinstance(indicators, list):
        indicators = []

    confidence = detection.get("phishing_probability") or detection.get("confidence_score") or scan_context.get("phishing_probability") or scan_context.get("confidence_score") or ""
    risk_level = detection.get("risk_level") or scan_context.get("risk_level") or ""
    mitre = scan_context.get("mitre_attack", [])
    if isinstance(mitre, list):
        mitre_technique = str(mitre[0]).strip() if mitre else ""
    else:
        mitre_technique = str(mitre or "").strip()
    containment = nist_actions.get("containment", []) if isinstance(nist_actions.get("containment"), list) else []
    recovery = nist_actions.get("eradication_recovery", []) if isinstance(nist_actions.get("eradication_recovery"), list) else []
    recommended = [str(item).strip() for item in [*containment[:1], *recovery[:1]] if str(item).strip()]
    return {
        "checked_url": scan_context.get("checked_url") or scan_context.get("url") or "",
        "verdict": detection.get("display_verdict") or detection.get("final_verdict") or scan_context.get("final_verdict") or "",
        "confidence": confidence,
        "risk_level": risk_level,
        "indicators": [str(item).strip() for item in indicators if str(item).strip()][:3],
        "MITRE": mitre_technique,
        "recommended_actions": recommended,
    }


def generate_chat_answer(user_question, scan_context, assistant_response_style="simple", conversation=None):
    recent_conversation = []
    if isinstance(conversation, list):
        for item in conversation[-2:]:
            if not isinstance(item, dict):
                continue
            role = str(item.get("role", "")).strip().lower()
            content = str(item.get("content", "")).strip()
            if role in {"user", "assistant"} and content:
                recent_conversation.append({"role": role, "content": content[:240]})
    return str(chat_chain.invoke({
        "user_question": user_question,
        "assistant_response_style": assistant_response_style,
        "scan_context": _compact_chat_context(scan_context),
        "conversation_history": recent_conversation,
    })).strip()
