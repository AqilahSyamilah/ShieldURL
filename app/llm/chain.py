from langchain_ollama import OllamaLLM
from langchain_core.output_parsers import JsonOutputParser
import os
from .prompts import chat_prompt, incident_prompt

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
    "num_predict": 180,
    "temperature": 0.2,
    "top_p": 0.8,
    "repeat_penalty": 1.1,
    "num_thread": os.cpu_count() or 4,
    "sync_client_kwargs": {"timeout": 22},
    "async_client_kwargs": {"timeout": 22},
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
    return {
        "url": scan_result["url"],
        "verdict": scan_result["verdict"],
        "confidence": scan_result["confidence"],
        "risk": scan_result["risk"],
        "format_instructions": parser.get_format_instructions(),
    }


def generate_ir_report(scan_result):
    prompt_inputs = _inputs(scan_result)
    raw_report = raw_chain.invoke(prompt_inputs)

    try:
        return _normalise_report(parser.parse(raw_report), scan_result.get("verdict", ""))
    except Exception as parse_error:
        return {
            "incident_summary": raw_report,
            "containment_actions": [],
            "mitre_attack_mapping": [],
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

    return {
        "url": scan_context.get("checked_url") or scan_context.get("url") or "",
        "verdict": detection.get("display_verdict") or detection.get("final_verdict") or scan_context.get("final_verdict") or "",
        "confidence": detection.get("phishing_probability") or detection.get("confidence_score") or scan_context.get("phishing_probability") or scan_context.get("confidence_score") or "",
        "risk": detection.get("risk_level") or scan_context.get("risk_level") or "",
        "suspicious_indicators": [str(item).strip() for item in indicators if str(item).strip()][:3],
        "mitre_attack": scan_context.get("mitre_attack", [])[:1] if isinstance(scan_context.get("mitre_attack"), list) else [],
        "recommended_actions": {
            "containment": nist_actions.get("containment", [])[:2] if isinstance(nist_actions.get("containment"), list) else [],
            "recovery": nist_actions.get("eradication_recovery", [])[:2] if isinstance(nist_actions.get("eradication_recovery"), list) else [],
        },
        "scope": scan_context.get("assistant_scope", ""),
    }


def generate_chat_answer(user_question, scan_context, assistant_response_style="simple", conversation=None):
    recent_conversation = []
    if isinstance(conversation, list):
        recent_conversation = conversation[-2:]
    context = {
        "scan_context": _compact_chat_context(scan_context),
        "recent_conversation": recent_conversation,
        "response_length": "Use at most 5 short bullet points.",
    }
    return str(chat_chain.invoke({
        "user_question": user_question,
        "assistant_response_style": assistant_response_style,
        "scan_context": context,
    })).strip()
