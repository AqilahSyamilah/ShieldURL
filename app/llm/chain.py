from langchain_ollama import OllamaLLM
from langchain_core.output_parsers import JsonOutputParser
from .prompts import chat_prompt, incident_prompt

llm = OllamaLLM(model="llama3.2")
parser = JsonOutputParser()

raw_chain = incident_prompt | llm
chain = raw_chain | parser
chat_chain = chat_prompt | llm


def _normalise_report(report):
    if not isinstance(report, dict):
        raise ValueError("LLM response is not a JSON object")

    containment_actions = _drop_placeholder_items(_safe_string_list(report.get("containment_actions")))
    eradication_actions = _drop_placeholder_items(_safe_string_list(report.get("eradication_recovery_actions")))
    post_incident_actions = _drop_placeholder_items(_safe_string_list(report.get("post_incident_recommendations")))

    return {
        "incident_summary": str(report.get("incident_summary", "")).strip(),
        "containment_actions": containment_actions or [
            "Block the URL and domain across DNS filtering, proxy, firewall, and email gateway.",
            "Review proxy, DNS, browser, and email logs to identify affected users.",
        ],
        "mitre_attack_mapping": _safe_string_list(report.get("mitre_attack_mapping")),
        "eradication_recovery_actions": eradication_actions or [
            "Reset credentials immediately if users entered login information.",
            "Enable MFA on affected accounts and review login history.",
        ],
        "post_incident_recommendations": post_incident_actions or [
            "Document the incident and preserve relevant scan, email, DNS, proxy, and endpoint evidence.",
            "Conduct phishing awareness training if users were affected.",
        ],
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
        return _normalise_report(parser.parse(raw_report))
    except Exception as parse_error:
        return {
            "incident_summary": raw_report,
            "containment_actions": [],
            "mitre_attack_mapping": [],
            "user_advisory": "",
            "raw_report": raw_report,
            "parse_error": str(parse_error),
        }


def generate_chat_answer(user_question, scan_context, assistant_response_style="simple"):
    return str(chat_chain.invoke({
        "user_question": user_question,
        "assistant_response_style": assistant_response_style,
        "scan_context": scan_context,
    })).strip()
