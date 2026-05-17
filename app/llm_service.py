import json
import os
import re
import socket
import urllib.error
import urllib.request
from typing import Any, Optional


LLM_REPORT = {
    "incident_summary": "",
    "incident_details": {
        "url": "",
        "final_verdict": "",
        "risk_level": "",
        "confidence_score": "",
        "clicked": "",
        "source": "",
        "timestamp": "",
    },
    "detection_analysis": [],
    "severity_priority": {
        "severity": "",
        "priority": "",
        "confidence_comment": "",
        "possible_impact": "",
    },
    "containment_actions": [],
    "eradication_recovery_actions": [],
    "post_incident_recommendations": [],
    "user_advisory": "",
    "mitre_attack_mapping": [],
    "analyst_notes": "",
    "generated_by": "unavailable",
    "error": "",
}


def _extract_json(text: str) -> dict[str, Any]:
    value = (text or "").strip()

    if value.startswith("```"):
        value = value.strip("`").strip()
        if value.lower().startswith("json"):
            value = value[4:].strip()

    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        start = value.find("{")
        end = value.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise
        parsed = json.loads(value[start:end + 1])

    if not isinstance(parsed, dict):
        raise ValueError("LLM response must be a JSON object")

    return parsed


def _safe_list(value: Any) -> list:
    if isinstance(value, list):
        return value
    if value in [None, ""]:
        return []
    return [str(value)]


def _dedupe_mitre_items(values: list[Any]) -> list[Any]:
    deduped: list[Any] = []
    seen: set[str] = set()

    for item in values:
        if isinstance(item, dict):
            mitre_id = _safe_text(item.get("id") or item.get("technique_id") or item.get("tactic_id"))
            mitre_name = _safe_text(item.get("name") or item.get("technique") or item.get("tactic"))
            key = f"{mitre_id.lower()}|{mitre_name.lower()}"
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
            continue

        text = _safe_text(item)
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(text)

    return deduped


def _safe_dict(value: Any, fallback: dict) -> dict:
    if isinstance(value, dict):
        merged = fallback.copy()
        merged.update(value)
        return merged
    return fallback.copy()


def _normalise_report(report: dict[str, Any]) -> dict[str, Any]:
    normalised = LLM_REPORT.copy()

    normalised["incident_summary"] = str(
        report.get("incident_summary")
        or report.get("incident_summary")
        or report.get("summary")
        or ""
    )

    normalised["incident_details"] = _safe_dict(
        report.get("incident_details"),
        LLM_REPORT["incident_details"],
    )

    for key in ["url", "final_verdict", "risk_level", "confidence_score", "clicked", "source", "timestamp"]:
        value = normalised["incident_details"].get(key)
        if value is None:
            normalised["incident_details"][key] = ""

    normalised["detection_analysis"] = _safe_list(
        report.get("detection_analysis")
        or report.get("detection_and_analysis")
        or report.get("analysis")
    )

    normalised["severity_priority"] = _safe_dict(
        report.get("severity_priority"),
        LLM_REPORT["severity_priority"],
    )

    normalised["containment_actions"] = _safe_list(
        report.get("containment_actions")
        or report.get("containment")
        or report.get("nist_response")
    )

    normalised["eradication_recovery_actions"] = _safe_list(
        report.get("eradication_recovery_actions")
        or report.get("recovery_actions")
        or report.get("incident_response")
    )

    normalised["post_incident_recommendations"] = _safe_list(
        report.get("post_incident_recommendations")
        or report.get("post_incident_activity")
        or report.get("post_incident")
    )

    normalised["user_advisory"] = str(
        report.get("user_advisory")
        or report.get("advisory")
        or ""
    )

    normalised["mitre_attack_mapping"] = _safe_list(
        report.get("mitre_attack_mapping")
        or report.get("mitre_techniques")
        or report.get("mitre")
    )

    normalised["analyst_notes"] = str(
        report.get("analyst_notes")
        or report.get("system_notes")
        or ""
    )

    normalised["generated_by"] = str(report.get("generated_by") or "llm")
    normalised["error"] = str(report.get("error") or "")

    return normalised


def _safe_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _is_risky_scan(scan_context: dict[str, Any]) -> bool:
    decision = _authoritative_decision(scan_context)
    risky_terms = ["phishing", "likely_phishing", "suspicious", "medium", "high"]
    return any(term in decision for term in risky_terms)


def _extract_scan_value(scan_context: dict[str, Any], *paths: tuple[str, ...], default: Any = "") -> Any:
    for path in paths:
        current: Any = scan_context
        found = True
        for part in path:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                found = False
                break
        if found and current not in [None, ""]:
            return current
    return default


def _format_confidence_percent(confidence: Any) -> str:
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


def _fallback_detection_analysis(scan_context: dict[str, Any], risky: bool) -> list[str]:
    reasons = _extract_scan_value(
        scan_context,
        ("heuristic_reasons",),
        ("heuristics", "reasons"),
        ("detection", "heuristic_reasons"),
        default=[],
    )
    if isinstance(reasons, list):
        cleaned = [_safe_text(item) for item in reasons if _safe_text(item)]
        if cleaned:
            return cleaned[:3]

    if risky:
        return [
            "The URL shows suspicious patterns consistent with phishing or deceptive link delivery.",
            "The scan context indicates indicators such as obfuscation, abnormal domain structure, or missing HTTPS trust signals.",
        ]
    return [
        "No immediate phishing threat was identified from the supplied scan context.",
        "Continue monitoring the URL context and user reports for any new suspicious activity.",
    ]


def _fallback_severity_priority(scan_context: dict[str, Any], risky: bool) -> dict[str, str]:
    confidence = _format_confidence_percent(
        _extract_scan_value(
            scan_context,
            ("confidence",),
            ("confidence_score",),
            ("detection", "confidence_score"),
            ("ml", "confidence_score"),
            default="unknown",
        )
    )
    if risky:
        return {
            "severity": "Medium",
            "priority": "High",
            "confidence_comment": f"The detection context indicates a phishing-related risk with confidence around {confidence}.",
            "possible_impact": "Users may be deceived into opening a phishing URL or disclosing credentials if they interact with the link.",
        }
    return {
        "severity": "Low",
        "priority": "Low",
        "confidence_comment": f"No immediate phishing threat was identified from the supplied scan context; model confidence was {confidence}.",
        "possible_impact": "No immediate phishing impact was identified, but continued monitoring is recommended.",
    }


def _incident_summary_needs_fallback(summary: str, scan_url: str = "") -> bool:
    summary = _safe_text(summary)
    if not summary:
        return True

    normalized = re.sub(r'[^a-z0-9 ]+', ' ', summary.lower()).strip()
    generic_patterns = [
        r'phishing incident detected at url',
        r'url scan detected( a)? phishing',
        r'suspicious url detected',
        r'phishing incident detected',
        r'phishing incident response report',
        r'url scan report',
        r'incident response report',
        r'url scan detected',
    ]
    if any(re.search(pattern, normalized) for pattern in generic_patterns):
        return True

    sentences = [s.strip() for s in re.split(r'[.!?]+', summary) if s.strip()]
    if len(sentences) != 2:
        return True

    if len(summary.strip().split()) < 20:
        return True

    required_terms = [
        'risk',
        'confidence',
        'suspicious',
        'indicator',
        'credential',
        'sensitive',
        'deceive',
    ]
    if not any(term in normalized for term in required_terms):
        return True

    if scan_url:
        url_key = scan_url.lower()
        if 'http' in url_key:
            if 'http' not in normalized and 'this url' not in normalized and 'submitted url' not in normalized:
                return True

    return False


def _fallback_incident_summary(scan_context: dict[str, Any]) -> str:
    verdict = _safe_text(
        _extract_scan_value(
            scan_context,
            ("final_verdict",),
            ("detection", "final_verdict"),
            ("overall", "verdict"),
            ("overall", "status"),
            default="unknown",
        )
    ).replace("_", " ").lower()
    risk = _safe_text(
        _extract_scan_value(
            scan_context,
            ("risk_level",),
            ("detection", "risk_level"),
            ("overall", "risk_level"),
            default="unknown",
        )
    ).lower()
    confidence_text = _format_confidence_percent(
        _extract_scan_value(
            scan_context,
            ("confidence",),
            ("confidence_score",),
            ("detection", "confidence_score"),
            ("ml", "confidence_score"),
            default="unknown",
        )
    )
    if _is_risky_scan(scan_context):
        return (
            f"The submitted URL was classified as {verdict or 'likely phishing'} with {risk or 'medium'} risk and {confidence_text} confidence based on suspicious indicators "
            "such as obfuscation, abnormal domain structure, and missing HTTPS trust signals. "
            "These indicators suggest possible user deception or credential exposure risk if the link is opened."
        )
    return (
        f"The submitted URL was reviewed with a {risk or 'low'} risk assessment and {confidence_text} confidence from the supplied scan context. "
        "No immediate phishing threat was identified, but standard monitoring and user caution remain appropriate."
    )


def _user_advisory_needs_fallback(advisory: str) -> bool:
    advisory = _safe_text(advisory)
    if not advisory:
        return True

    normalized = re.sub(r'[^a-z0-9 ]+', ' ', advisory.lower()).strip()
    generic_patterns = [
        r'be cautious when clicking suspicious links',
        r'avoid unfamiliar links',
        r'be careful with suspicious links',
        r'do not click suspicious links',
        r'avoid suspicious links',
        r'be cautious when clicking on links from unknown sources',
    ]
    if any(re.search(pattern, normalized) for pattern in generic_patterns):
        return True

    required_terms = [
        "do not open",
        "login",
        "otp",
        "banking",
        "personal data",
        "report",
        "it",
    ]
    return not any(term in normalized for term in required_terms)


def _fallback_user_advisory(risky: bool = True) -> str:
    if risky:
        return (
            "Do not open this URL or enter login credentials, OTP, banking information, or personal data. "
            "Report the link to IT/security immediately."
        )
    return (
        "No immediate phishing threat was identified from the supplied scan context. "
        "If the URL was unsolicited or unexpected, report it to IT/security before interacting with it."
    )


def _truncate_sentences(text: str, max_sentences: int = 2) -> str:
    text = _safe_text(text)
    if not text:
        return ""
    parts = re.split(r'(?<=[.!?])\s+', text)
    parts = [part.strip() for part in parts if part.strip()]
    return " ".join(parts[:max_sentences])


def _truncate_list(values: list[Any], limit: int) -> list[Any]:
    return values[:limit]


def _drop_placeholder_actions(values: list[Any]) -> list[Any]:
    placeholder_terms = [
        "action 1",
        "action 2",
        "recommendation 1",
        "recommendation 2",
        "practical containment step",
        "practical investigation step",
        "placeholder",
        "example",
        "sample label",
        "generic template",
    ]
    cleaned = []
    for value in values:
        text = _safe_text(value)
        if not text:
            continue
        lowered = text.lower()
        if any(term in lowered for term in placeholder_terms):
            continue
        cleaned.append(value)
    return cleaned


def _apply_post_processing(report: dict[str, Any], scan_context: dict[str, Any]) -> dict[str, Any]:
    fallback_report = fallback_llm_report(scan_context, report.get("error", "") or "Partial LLM output")

    summary = report.get("incident_summary", "")
    if _incident_summary_needs_fallback(summary, str(scan_context.get("url", ""))):
        report["incident_summary"] = _fallback_incident_summary(scan_context)
    else:
        report["incident_summary"] = _truncate_sentences(summary, 2)

    advisory = report.get("user_advisory", "")
    if _user_advisory_needs_fallback(advisory):
        report["user_advisory"] = _fallback_user_advisory(_is_risky_scan(scan_context))
    else:
        report["user_advisory"] = _truncate_sentences(_safe_text(advisory), 2)

    report["containment_actions"] = _truncate_list(_drop_placeholder_actions(_safe_list(report.get("containment_actions"))), 2)
    report["eradication_recovery_actions"] = _truncate_list(_drop_placeholder_actions(_safe_list(report.get("eradication_recovery_actions"))), 2)
    report["post_incident_recommendations"] = _truncate_list(_drop_placeholder_actions(_safe_list(report.get("post_incident_recommendations"))), 2)
    report["detection_analysis"] = _truncate_list(_safe_list(report.get("detection_analysis")), 3)
    report["analyst_notes"] = _truncate_sentences(report.get("analyst_notes", ""), 1)

    incident_details = report.get("incident_details", {})
    if not isinstance(incident_details, dict):
        incident_details = {}
    for key, fallback_value in fallback_report["incident_details"].items():
        if incident_details.get(key) in [None, ""]:
            incident_details[key] = fallback_value
    report["incident_details"] = incident_details

    if not report["detection_analysis"]:
        report["detection_analysis"] = fallback_report["detection_analysis"]

    severity_priority = report.get("severity_priority", {})
    if not isinstance(severity_priority, dict):
        severity_priority = {}
    fallback_severity = fallback_report["severity_priority"]
    for key, fallback_value in fallback_severity.items():
        if severity_priority.get(key) in [None, ""]:
            severity_priority[key] = fallback_value
    report["severity_priority"] = severity_priority

    if not report["containment_actions"]:
        report["containment_actions"] = fallback_report["containment_actions"]
    if not report["eradication_recovery_actions"]:
        report["eradication_recovery_actions"] = fallback_report["eradication_recovery_actions"]
    if not report["post_incident_recommendations"]:
        report["post_incident_recommendations"] = fallback_report["post_incident_recommendations"]
    if not report.get("mitre_attack_mapping"):
        report["mitre_attack_mapping"] = fallback_report["mitre_attack_mapping"]
    report["mitre_attack_mapping"] = _truncate_list(_dedupe_mitre_items(_safe_list(report.get("mitre_attack_mapping"))), 1)
    if not report["analyst_notes"]:
        report["analyst_notes"] = fallback_report["analyst_notes"]

    return report


def _build_prompt(scan_context: dict[str, Any]) -> str:
    prompt = {
        "task": "Return valid JSON only for a concise URL incident report.",
        "rules": [
            "Use scan_context only.",
            "incident_summary must be 1-2 analytical sentences, never a title.",
            "For phishing or suspicious URLs, explain what was detected, why it is suspicious, and likely impact.",
            "containment_actions max 2 items.",
            "eradication_recovery_actions max 2 items.",
            "post_incident_recommendations max 2 items.",
            "user_advisory max 2 sentences and direct for end users.",
            "If clicked is false or unknown, do not assume compromise or require password reset.",
            "Use at most 1 MITRE item. Prefer T1566.002 for deceptive phishing links when justified.",
            "If verdict is safe or low risk, do not describe the URL as phishing or malicious.",
            "Do not output placeholders, sample labels, example text, or generic templates.",
            "Always produce actionable recommendations based on scan_context.",
        ],
        "schema_keys": [
            "incident_summary",
            "incident_details",
            "detection_analysis",
            "severity_priority",
            "containment_actions",
            "eradication_recovery_actions",
            "post_incident_recommendations",
            "user_advisory",
            "mitre_attack_mapping",
            "analyst_notes",
        ],
        "scan_context": scan_context,
    }

    return json.dumps(prompt, separators=(",", ":"))

def _mitre_validation_error(report: dict[str, Any], scan_context: dict[str, Any]) -> str:
    decision = _authoritative_decision(scan_context)

    if any(term in decision for term in ["phishing", "likely_phishing", "suspicious", "medium", "high"]):
        mappings = report.get("mitre_attack_mapping", [])
        if mappings:
            first = mappings[0]
            if isinstance(first, dict):
                mitre_id = str(first.get("id", "")).strip()
                mitre_name = str(first.get("name", "")).strip().lower()

                if mitre_id == "T1056" or mitre_name == "phishing":
                    return "For phishing URLs, do not use T1056 or name it as phishing. Prefer T1566.002 Spearphishing Link when justified."
    return ""

def _ollama_generate(prompt: str, model: str, base_url: str, timeout: int) -> str:
    url = base_url.rstrip("/") + "/api/generate"

    payload = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
                "format": "json",
            "options": {
                "temperature": 0,
                "num_predict": 180,
            },
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read().decode("utf-8"))

    text = body.get("response", "")
    if not text:
        raise ValueError("Ollama returned an empty response")

    return text


def fallback_llm_report(
    scan_context: Optional[dict[str, Any]] = None,
    error_message: str = "AI report generation is currently unavailable.",
) -> dict[str, Any]:
    context = scan_context or {}
    risky = _is_risky_scan(context)
    report = json.loads(json.dumps(LLM_REPORT))
    confidence_value = _extract_scan_value(
        context,
        ("confidence",),
        ("confidence_score",),
        ("detection", "confidence_score"),
        ("ml", "confidence_score"),
        default="",
    )
    report["incident_summary"] = _fallback_incident_summary(context)
    report["incident_details"] = {
        "url": _extract_scan_value(context, ("url",), ("incident_details", "url"), default=""),
        "final_verdict": _extract_scan_value(
            context, ("final_verdict",), ("detection", "final_verdict"), ("overall", "verdict"), default=""
        ),
        "risk_level": _extract_scan_value(
            context, ("risk_level",), ("detection", "risk_level"), ("overall", "risk_level"), default=""
        ),
        "confidence_score": _format_confidence_percent(confidence_value) if confidence_value not in ["", None] else "",
        "clicked": _extract_scan_value(context, ("clicked",), ("incident_details", "clicked"), default=""),
        "source": _extract_scan_value(context, ("source",), ("overall", "source"), default=""),
        "timestamp": _extract_scan_value(context, ("timestamp",), ("incident_details", "timestamp"), default=""),
    }
    report["detection_analysis"] = _fallback_detection_analysis(context, risky)
    report["severity_priority"] = _fallback_severity_priority(context, risky)
    if risky:
        report["containment_actions"] = [
            "Block or avoid the suspicious URL.",
            "Warn users not to interact with the link.",
        ]
        report["eradication_recovery_actions"] = [
            "Verify whether any user accessed the URL.",
            "Remove the phishing link from related communications if applicable.",
        ]
        report["post_incident_recommendations"] = [
            "Document the incident and monitor for repeated phishing attempts.",
            "Update user awareness guidance on phishing and suspicious URLs.",
        ]
        report["mitre_attack_mapping"] = [
            {
                "id": "T1566.002",
                "name": "Spearphishing Link",
                "rationale": "The URL appears to be a deceptive phishing link intended to lure user clicks.",
            }
        ]
        report["analyst_notes"] = "LLM generation timed out or was unavailable; fallback phishing response guidance was returned."
    else:
        report["containment_actions"] = [
            "No immediate blocking action is required based on the supplied scan context.",
            "Monitor for any user reports or repeated suspicious submissions involving the URL.",
        ]
        report["eradication_recovery_actions"] = [
            "If the URL appeared in communications, verify that no follow-up reports indicate suspicious behavior.",
            "Retain the scan result for reference in case new indicators emerge later.",
        ]
        report["post_incident_recommendations"] = [
            "Document the review outcome and maintain standard monitoring.",
            "Remind users to verify unexpected links before interacting with them.",
        ]
        report["mitre_attack_mapping"] = []
        report["analyst_notes"] = "LLM generation timed out or was unavailable; fallback monitoring guidance was returned."
    report["user_advisory"] = _fallback_user_advisory(risky)
    report["generated_by"] = "fallback"
    report["error"] = str(error_message or "LLM timeout or unavailable")
    return report


def _authoritative_decision(scan_context: dict[str, Any]) -> str:
    candidates = []

    detection = scan_context.get("detection")
    if isinstance(detection, dict):
        candidates.extend([
            detection.get("final_verdict"),
            detection.get("risk_level"),
            detection.get("confidence_score"),
        ])

    overall = scan_context.get("overall")
    if isinstance(overall, dict):
        candidates.extend([
            overall.get("status"),
            overall.get("verdict"),
            overall.get("risk_level"),
        ])

    candidates.extend([
        scan_context.get("final_verdict"),
        scan_context.get("risk_level"),
    ])

    return " ".join(str(item).lower() for item in candidates if item is not None)


def _is_safe_decision(scan_context: dict[str, Any]) -> bool:
    decision = _authoritative_decision(scan_context)
    safe_terms = ["legitimate", "likely_legitimate", "safe", "low"]
    risky_terms = ["phishing", "likely_phishing", "suspicious", "medium", "high"]
    return any(term in decision for term in safe_terms) and not any(term in decision for term in risky_terms)


def _report_validation_error(report: dict[str, Any], scan_context: dict[str, Any]) -> str:
    if _is_safe_decision(scan_context):
        if report.get("mitre_attack_mapping"):
            return "The scan decision is safe/legitimate, so mitre_attack_mapping must be an empty array."

        unsafe_text = " ".join([
            str(report.get("incident_summary", "")),
            str(report.get("user_advisory", "")),
            str(report.get("analyst_notes", "")),
        ]).lower()

        unsafe_phrases = [
            "phishing attack",
            "block this url",
            "credential theft",
            "malware",
            "avoid this link",
            "malicious website",
        ]

        for phrase in unsafe_phrases:
            if phrase in unsafe_text:
                return (
                    "The scan decision is safe/legitimate, so the report must not describe the URL as malicious, phishing, or require blocking."
                )

    return ""


def generate_url_report(scan_context: dict[str, Any]) -> dict[str, Any]:
    if os.environ.get("SKIP_LLM", "0") == "1":
        return fallback_llm_report(scan_context, "LLM generation skipped via SKIP_LLM")

    model = os.environ.get("OLLAMA_MODEL", "llama3.2")
    base_url = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    timeout = min(int(os.environ.get("OLLAMA_TIMEOUT", "45")), 45)

    try:
        prompt = _build_prompt(scan_context)
        llm_text = _ollama_generate(prompt, model, base_url, timeout)
        parsed = _extract_json(llm_text)
        parsed["generated_by"] = f"ollama:{model}"

        report = _apply_post_processing(_normalise_report(parsed), scan_context)
        validation_error = _report_validation_error(report, scan_context)
        if not validation_error:
            validation_error = _mitre_validation_error(report, scan_context)

        if validation_error:
            report["error"] = validation_error
        return report

    except urllib.error.URLError as exc:
        return fallback_llm_report(scan_context, f"Ollama is unavailable at {base_url}: {exc.reason}")

    except TimeoutError:
        return fallback_llm_report(scan_context, "LLM generation timed out after 45 seconds")

    except socket.timeout:
        return fallback_llm_report(scan_context, "LLM generation timed out after 45 seconds")

    except Exception as exc:
        return fallback_llm_report(scan_context, str(exc))
