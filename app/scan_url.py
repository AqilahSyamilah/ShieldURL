import sys
import os
import time
import json
import joblib
import re
import traceback
from typing import Any, Optional

try:
    from .features import MODEL_PATH, extract_features, features_dataframe, get_domain
    from .llm.chain import generate_ir_report
    from .llm_service import fallback_llm_report
except ImportError:
    from features import MODEL_PATH, extract_features, features_dataframe, get_domain
    from llm.chain import generate_ir_report
    from llm_service import fallback_llm_report


AI_REPORT_FALLBACK_MESSAGE = "AI report unavailable, but detection result is still valid."


def _build_ir_llm_report(url: str, verdict: str, confidence: float, risk: str) -> dict[str, Any]:
    ir_scan_result = {
        "url": url,
        "verdict": verdict.upper(),
        "confidence": float(confidence),
        "risk": risk.upper(),
    }

    try:
        report = generate_ir_report(ir_scan_result)
        if not isinstance(report, dict):
            raise ValueError("LLM report must be a JSON object")

        raw_report = str(report.get("raw_report") or report.get("report") or report.get("incident_summary") or "").strip()
        incident_summary = str(report.get("incident_summary", "")).strip()
        containment_actions = report.get("containment_actions") if isinstance(report.get("containment_actions"), list) else []
        mitre_attack_mapping = report.get("mitre_attack_mapping") if isinstance(report.get("mitre_attack_mapping"), list) else []
        eradication_recovery_actions = report.get("eradication_recovery_actions") if isinstance(report.get("eradication_recovery_actions"), list) else []
        post_incident_recommendations = report.get("post_incident_recommendations") if isinstance(report.get("post_incident_recommendations"), list) else []
        user_advisory = str(report.get("user_advisory", "")).strip()

        return {
            "generated_by": "langchain_ollama",
            "report": raw_report or incident_summary,
            "incident_summary": incident_summary or raw_report,
            "containment_actions": containment_actions,
            "mitre_attack_mapping": mitre_attack_mapping,
            "eradication_recovery_actions": eradication_recovery_actions,
            "post_incident_recommendations": post_incident_recommendations,
            "user_advisory": user_advisory,
            "raw_report": raw_report,
            "parse_error": report.get("parse_error", ""),
        }
    except Exception as exc:
        return {
            "generated_by": "fallback",
            "error": AI_REPORT_FALLBACK_MESSAGE,
            "details": str(exc),
            "incident_summary": AI_REPORT_FALLBACK_MESSAGE,
            "report": AI_REPORT_FALLBACK_MESSAGE,
            "containment_actions": [],
            "mitre_attack_mapping": [],
            "eradication_recovery_actions": [],
            "post_incident_recommendations": [],
            "user_advisory": AI_REPORT_FALLBACK_MESSAGE,
        }


def run_scan(url: str, clicked: Optional[bool] = False) -> dict[str, Any]:
    try:
        start_total = time.perf_counter()
        start_detection = time.perf_counter()
        features = extract_features(url)

        # Load the trained model from disk.
        model = joblib.load(MODEL_PATH)

        # Keep the incoming features in the same order the model was trained on.
        expected_columns = list(getattr(model, "feature_names_in_", [])) or list(
            getattr(model, "feature_columns_", [])
        )
        df = features_dataframe(features, expected_columns or None)

        # Run the model prediction and collect confidence if available.
        try:
            prediction = model.predict(df)[0]
            confidence = 0.0

            if hasattr(model, 'predict_proba'):
                proba = model.predict_proba(df)[0]
                try:
                    class_idx = list(model.classes_).index(prediction)
                    confidence = proba[class_idx]
                except Exception:
                    confidence = max(proba)

            status = "safe"
            if int(prediction) == 1:
                status = "phishing"

        except Exception:
            # Fall back to a small ruleset if the model cannot score the URL.
            score = 0
            if features['UsingIP'] == -1:
                score += 1
            if features['LongURL'] == -1:
                score += 1
            if features['ShortURL'] == -1:
                score += 1
            if features['Symbol@'] == -1:
                score += 1

            if score >= 2:
                status = "phishing"
                confidence = 0.85
            elif score == 1:
                status = "suspicious"
                confidence = 0.60
            else:
                status = "safe"
                confidence = 0.90

        # Apply a few extra URL checks after the model result.
        heuristic_reasons = []

        risky_tlds = ['.ru', '.cn', '.xyz', '.top', '.work', '.info', '.tk', '.ml', '.ga', '.cf', '.gq']
        domain = get_domain(url)

        if any(domain.endswith(tld) for tld in risky_tlds):
            status = "suspicious" if status == "safe" else status
            heuristic_reasons.append(f"uses a high-risk Top-Level Domain ({domain.split('.')[-1]})")
            if status == "suspicious" and confidence > 0.5:
                confidence = 0.65

        # Leetspeak in the host is a strong typosquatting signal.
        if re.search(r"[a-z][0-9][a-z]", domain.lower()):
            status = "phishing"
            heuristic_reasons.append("contains obfuscated characters (leetspeak) often used in typosquatting")
            confidence = 0.85

        # Login and account language often appears in lure URLs.
        suspicious_keywords = ['login', 'secure', 'account', 'update', 'verify', 'wallet', 'banking']
        if any(kw in url.lower() for kw in suspicious_keywords):
            if status == "safe":
                status = "suspicious"
                heuristic_reasons.append("contains sensitive keywords commonly targeted by phishers")

        # Recalculate the risk level after the heuristic adjustments.
        risk_level = "low"
        if status == "phishing":
            risk_level = "high"
        elif status == "suspicious":
            risk_level = "medium"

        detection_seconds = time.perf_counter() - start_detection

        start_llm = time.perf_counter()
        if os.environ.get("SKIP_LLM", "0") == "1":
            llm_output = {
                "generated_by": "fallback",
                "error": AI_REPORT_FALLBACK_MESSAGE,
                "details": "LLM generation skipped via SKIP_LLM",
                "incident_summary": AI_REPORT_FALLBACK_MESSAGE,
                "report": AI_REPORT_FALLBACK_MESSAGE,
                "containment_actions": [],
                "mitre_attack_mapping": [],
                "eradication_recovery_actions": [],
                "post_incident_recommendations": [],
                "user_advisory": AI_REPORT_FALLBACK_MESSAGE,
            }
        else:
            llm_output = _build_ir_llm_report(url, status, float(confidence), risk_level)
        llm_seconds = time.perf_counter() - start_llm

        total_seconds = time.perf_counter() - start_total

        return {
            "success": True,
            "url": url,
            "clicked": clicked,
            "detection": {
                "final_verdict": status,
                "risk_level": risk_level,
                "confidence_score": float(confidence),
                "features": features,
                "heuristic_reasons": heuristic_reasons,
            },
            "llm_report": llm_output,
            "timing": {
                "detection_seconds": round(detection_seconds, 3),
                "llm_seconds": round(llm_seconds, 3),
                "total_seconds": round(total_seconds, 3),
            },
        }
    except Exception as exc:
        failure_context = {
            "url": url,
            "clicked": clicked,
        }
        return {
            "success": False,
            "url": url,
            "clicked": clicked,
            "error": str(exc),
            "traceback": traceback.format_exc(),
            "llm_report": fallback_llm_report(failure_context, str(exc)),
            "timing": {
                "total_seconds": round(time.perf_counter() - start_total, 3) if "start_total" in locals() else 0,
            },
        }


def main():
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'No URL provided'}))
        return

    url = sys.argv[1]
    result = run_scan(url, False)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
