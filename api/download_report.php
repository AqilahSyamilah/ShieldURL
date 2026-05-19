<?php
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

require_once '../config/db.php';
require_once '../shared/audit.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id']) || !isset($_GET['id'])) {
    http_response_code(403);
    exit('Access denied');
}

function h($value)
{
    return htmlspecialchars((string)($value ?? ''), ENT_QUOTES, 'UTF-8');
}

function safe_decode($value, $fallback = [])
{
    if ($value === null || $value === '') {
        return $fallback;
    }
    $decoded = json_decode($value, true);
    return json_last_error() === JSON_ERROR_NONE ? $decoded : $fallback;
}

function normalize_list($value)
{
    if ($value === null || $value === '') {
        return [];
    }
    if (is_string($value)) {
        $decoded = json_decode($value, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            return normalize_list($decoded);
        }
        return array_values(array_filter(array_map('trim', preg_split('/\r\n|\r|\n|;/', $value))));
    }
    if (!is_array($value)) {
        return [(string)$value];
    }
    $out = [];
    foreach ($value as $item) {
        if (is_array($item)) {
            $out[] = $item['action'] ?? $item['step'] ?? $item['description'] ?? $item['name'] ?? json_encode($item);
        } elseif ($item !== null && $item !== '') {
            $out[] = (string)$item;
        }
    }
    return array_values(array_filter($out));
}

function feature_value($features, $keys, $fallback = '')
{
    foreach ($keys as $key) {
        if (is_array($features) && array_key_exists($key, $features)) {
            $value = $features[$key];
            if (is_bool($value)) {
                return $value ? 'Yes' : 'No';
            }
            if ($value === -1) {
                return 'Detected';
            }
            if ($value === 1) {
                return 'Clean';
            }
            if ($value === 0) {
                return 'Neutral';
            }
            return (string)$value;
        }
    }
    return $fallback;
}

function feature_label($key)
{
    $label = str_replace(['_', '-'], ' ', (string)$key);
    $label = preg_replace('/(?<!^)([A-Z])/', ' $1', $label);
    return ucwords(trim($label));
}

function display_feature_value($value)
{
    if (is_bool($value)) {
        return $value ? 'Yes' : 'No';
    }
    if ($value === null || $value === '') {
        return 'N/A';
    }
    if (is_array($value)) {
        return json_encode($value);
    }
    if ($value === -1) {
        return 'Suspicious';
    }
    if ($value === 1) {
        return 'Clean';
    }
    if ($value === 0) {
        return 'Neutral';
    }
    return (string)$value;
}

function severity_from($status, $riskLevel, $confidence)
{
    $status = strtolower((string)$status);
    $risk = strtolower((string)$riskLevel);
    if ($status === 'phishing' && ($confidence >= 0.85 || $risk === 'high')) {
        return 'Critical';
    }
    if ($status === 'phishing') {
        return 'High';
    }
    if ($status === 'suspicious' || $risk === 'medium') {
        return 'Medium';
    }
    return 'Low';
}

function status_icon($status)
{
    $status = strtolower((string)$status);
    if ($status === 'phishing') {
        return '!';
    }
    if ($status === 'suspicious') {
        return '?';
    }
    return '✓';
}

function suspicious_keywords_from_url($url)
{
    $keywords = ['login', 'verify', 'secure', 'account', 'update', 'signin', 'wallet', 'bank', 'payment', 'password', 'otp'];
    $found = [];
    $lower = strtolower($url);
    foreach ($keywords as $keyword) {
        if (strpos($lower, $keyword) !== false) {
            $found[] = $keyword;
        }
    }
    return $found;
}

function domain_parts($url)
{
    $host = parse_url($url, PHP_URL_HOST);
    if (!$host) {
        $host = parse_url('http://' . $url, PHP_URL_HOST);
    }
    $host = strtolower($host ?: '');
    $parts = $host !== '' ? explode('.', $host) : [];
    $tld = count($parts) > 1 ? end($parts) : '';
    $subdomains = max(0, count($parts) - 2);
    return [$host, $tld, $subdomains];
}

function indicator_detected($value)
{
    $normalized = strtolower((string)$value);
    return in_array($normalized, ['detected', 'yes', 'true', '-1', '1'], true);
}

$db = new Database();
$conn = $db->getConnection();

$reportId = (int)$_GET['id'];
$isAdmin = ($_SESSION['role'] ?? '') === 'admin';
if ($isAdmin) {
    $stmt = $conn->prepare("SELECT * FROM url_logs WHERE id = ?");
    $stmt->execute([$reportId]);
} else {
    $stmt = $conn->prepare("SELECT * FROM url_logs WHERE id = ? AND user_id = ?");
    $stmt->execute([$reportId, $_SESSION['user_id']]);
}
$report = $stmt->fetch();

if (!$report) {
    audit_log($conn, 'report_download', 'Report download failed for report ID ' . $reportId, 'failed');
    http_response_code(404);
    exit('Report not found');
}

audit_log($conn, 'report_download', "Downloaded report #{$report['id']} for URL '{$report['url']}'", 'success');

$features = safe_decode($report['features'] ?? '', []);
$mitre = safe_decode($report['mitre_attack_json'] ?? '', []);
$nistSteps = normalize_list(safe_decode($report['nist_response_json'] ?? '', []));
$irSteps = normalize_list(safe_decode($report['incident_response_text'] ?? '', []));
$analysis = safe_decode($report['analysis_result'] ?? '', []);
$url = $report['url'] ?? '';
[$domain, $tld, $subdomainCount] = domain_parts($url);

$status = strtolower((string)($report['status'] ?? 'safe'));
$displayStatus = $analysis['display_status'] ?? (($status === 'phishing' && (($analysis['confidence_score'] ?? $report['confidence_score'] ?? 0) < 0.70)) ? 'potentially suspicious' : $status);
$displayStatusNormalized = strtolower((string)$displayStatus);
$threatStatusClass = strpos($displayStatusNormalized, 'suspicious') !== false ? 'suspicious' : $status;
$confidenceRaw = (float)($report['confidence_score'] ?? 0);
$confidence = $confidenceRaw <= 1 ? $confidenceRaw * 100 : $confidenceRaw;
$confidenceNormalized = max(0, min(1, $confidence / 100));
$riskLevel = $report['risk_level'] ?? 'low';
$severity = severity_from($status, $riskLevel, $confidenceNormalized);
$riskScore = number_format($confidenceNormalized * 10, 1);
$scanDuration = $analysis['debug']['php_total_seconds'] ?? $analysis['debug']['curl_total_seconds'] ?? 'N/A';
$engine = 'ShieldURL URL Detection + Incident Response';
$modelPolicy = $analysis['model_policy'] ?? 'The system uses advanced URL detection analysis to identify suspicious website patterns.';
if (preg_match('/lexical model|false negatives|threshold|recall/i', (string)$modelPolicy)) {
    $modelPolicy = 'The system uses advanced URL detection analysis to identify suspicious website patterns.';
}
$selectedThresholdRaw = (float)($analysis['selected_threshold'] ?? ($analysis['ml']['selected_threshold'] ?? 0.5));
$selectedThreshold = $selectedThresholdRaw <= 1 ? $selectedThresholdRaw * 100 : $selectedThresholdRaw;
$systemDetection = strtoupper($status);
$protocol = parse_url($url, PHP_URL_SCHEME) ?: 'http';
$httpsStatus = $protocol === 'https' ? 'Valid HTTPS' : 'Non-HTTPS';
$keywords = suspicious_keywords_from_url($url);
$redirectFound = feature_value($features, ['Redirect', 'redirect', 'double_slash_redirecting'], '');
$longUrl = feature_value($features, ['LongURL', 'URLURL_Length', 'url_length', 'URL_Length'], '');
$brandTerms = array_values(array_intersect($keywords, ['login', 'verify', 'secure', 'account', 'update', 'signin', 'wallet', 'bank', 'payment']));
$suspiciousTlds = ['zip', 'mov', 'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'icu', 'click', 'work'];
$riskIndicators = [];
if ($protocol !== 'https') {
    $riskIndicators[] = 'Non-HTTPS';
}
if ($tld !== '' && in_array($tld, $suspiciousTlds, true)) {
    $riskIndicators[] = 'Suspicious TLD';
}
if (indicator_detected($longUrl) || strlen($url) > 75) {
    $riskIndicators[] = 'Long URL';
}
if (!empty($brandTerms)) {
    $riskIndicators[] = 'Possible Brand Impersonation';
}
if (indicator_detected($redirectFound)) {
    $riskIndicators[] = 'Redirect Detected';
}
$userAdvisory = $report['user_advisory_text'] ?: 'Do not enter credentials, OTP, banking information, or personal data. Report this URL to IT/security.';
if ($displayStatusNormalized === 'potentially suspicious') {
    $userAdvisory = 'Suspicious signals were detected, but this URL is not confirmed as phishing. Review the URL carefully and verify the destination before entering credentials or sensitive information.';
}

$executiveSummary = normalize_list($report['llm_summary'] ?? '');
if ($displayStatusNormalized === 'potentially suspicious') {
    $executiveSummary = [
        'This URL shows suspicious characteristics, but it is not confirmed phishing. Users should verify the website carefully before entering passwords, OTPs, or sensitive information.',
    ];
}
if (empty($executiveSummary)) {
    if ($status === 'phishing') {
        $executiveSummary = [
            $displayStatusNormalized === 'potentially suspicious'
                ? 'This URL shows suspicious characteristics, but it is not confirmed phishing. Users should verify the website carefully before entering passwords, OTPs, or sensitive information.'
                : 'Threat likely attempts credential harvesting or user deception.',
            'Suspicious domain or URL indicators were detected during analysis.',
            'The system uses advanced URL detection analysis to identify suspicious website patterns.',
            $displayStatusNormalized === 'potentially suspicious'
                ? 'Review the URL carefully and verify the destination before entering credentials or sensitive information.'
                : 'Users may be redirected to fake login portals or unsafe pages.',
        ];
    } elseif ($status === 'suspicious') {
        $executiveSummary = [
            'The URL contains suspicious indicators that require caution.',
            'User interaction should be limited until the destination is verified.',
            'Security teams should review the technical evidence before allowing access.',
        ];
    } else {
        $executiveSummary = [
            'No high-risk phishing indicators were identified by the current scan.',
            'Continue monitoring if the URL was received through an unusual channel.',
            'Users should still avoid sharing credentials unless the destination is trusted.',
        ];
    }
}
if (!in_array($modelPolicy, $executiveSummary, true)) {
    $executiveSummary[] = $modelPolicy;
}

$timeline = [
    ['Detection & Analysis', 'Search', array_merge(['Review the URL verdict, confidence, and technical indicators.'], array_slice($nistSteps, 0, 2))],
    ['Containment', 'Shield', !empty($irSteps) ? array_slice($irSteps, 0, 3) : ['Block or quarantine the URL if risk is confirmed.', 'Warn affected users not to interact with the link.']],
    ['Eradication', 'Clean', array_slice($nistSteps, 2, 3) ?: ['Remove malicious messages, tickets, or references from user-accessible systems.']],
    ['Recovery', 'Restore', array_slice($irSteps, 3, 3) ?: ['Reset exposed credentials if any user submitted information.', 'Validate impacted accounts before returning to normal activity.']],
    ['Post-Incident Actions', 'Report', ['Document the indicators observed in this report.', 'Tune awareness, email, and web controls using the evidence collected.']],
];
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Incident Report #<?php echo h($report['id']); ?> - ShieldURL</title>
    <style>
        * { box-sizing: border-box; }
        :root {
            --navy: #07182d;
            --blue: #123b6d;
            --accent: #2563eb;
            --gold: #d4a84a;
            --line: #dbe4ef;
            --muted: #64748b;
            --paper: #f6f9fc;
            --danger: #dc2626;
            --warn: #d97706;
            --safe: #15803d;
        }
        body {
            margin: 0;
            background: #e8eef6;
            color: #0f172a;
            font-family: "Segoe UI", Arial, sans-serif;
            line-height: 1.45;
            print-color-adjust: exact;
            -webkit-print-color-adjust: exact;
        }
        .report-page {
            width: min(1180px, calc(100% - 32px));
            margin: 24px auto;
            background: #ffffff;
            border: 1px solid var(--line);
            box-shadow: 0 18px 50px rgba(7, 24, 45, 0.18);
        }
        .report-header {
            display: grid;
            grid-template-columns: minmax(0, 1fr) auto;
            gap: 24px;
            padding: 28px 32px;
            background: linear-gradient(135deg, var(--navy) 0%, var(--blue) 72%, #1d4ed8 100%);
            color: #ffffff;
        }
        .brand-block {
            display: flex;
            gap: 18px;
            align-items: center;
            min-width: 0;
        }
        .brand-block img {
            width: 76px;
            height: 76px;
            object-fit: contain;
            filter: drop-shadow(0 8px 18px rgba(0,0,0,0.32));
        }
        .eyebrow {
            margin: 0 0 4px;
            color: #bfdbfe;
            text-transform: uppercase;
            font-size: 0.78rem;
            font-weight: 800;
            letter-spacing: 0.12em;
        }
        h1 {
            margin: 0;
            font-size: clamp(1.8rem, 4vw, 2.6rem);
            line-height: 1.1;
        }
        .header-meta {
            min-width: 280px;
            display: grid;
            gap: 8px;
            font-size: 0.92rem;
        }
        .meta-row {
            display: flex;
            justify-content: space-between;
            gap: 18px;
            border-bottom: 1px solid rgba(255,255,255,0.16);
            padding-bottom: 6px;
        }
        .meta-row span:first-child { color: #bfdbfe; }
        .report-actions {
            display: flex;
            gap: 8px;
            justify-content: flex-end;
            margin-top: 10px;
        }
        .report-btn {
            border: 1px solid rgba(255,255,255,0.32);
            background: rgba(255,255,255,0.12);
            color: #ffffff;
            border-radius: 8px;
            padding: 8px 12px;
            font: inherit;
            font-weight: 800;
            cursor: pointer;
            text-decoration: none;
        }
        .report-btn.primary {
            background: var(--gold);
            border-color: var(--gold);
            color: #08203c;
        }
        .report-body {
            padding: 26px 32px 34px;
            display: grid;
            gap: 20px;
        }
        .section-card {
            border: 1px solid var(--line);
            border-radius: 14px;
            background: #ffffff;
            overflow: hidden;
        }
        .section-title {
            margin: 0;
            padding: 16px 18px;
            background: #f8fbff;
            border-bottom: 1px solid var(--line);
            color: #0b1f3a;
            font-size: 1rem;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }
        .threat-card {
            display: grid;
            grid-template-columns: 1.2fr 2fr;
            gap: 0;
            border-radius: 16px;
            overflow: hidden;
            border: 1px solid var(--line);
            box-shadow: 0 12px 28px rgba(15, 23, 42, 0.08);
        }
        .threat-status {
            padding: 26px;
            background: #0b1f3a;
            color: #ffffff;
            display: grid;
            align-content: center;
            gap: 12px;
        }
        .threat-status.phishing { background: linear-gradient(145deg, #3b0d12, #991b1b); }
        .threat-status.suspicious { background: linear-gradient(145deg, #432006, #b45309); }
        .threat-status.safe { background: linear-gradient(145deg, #052e16, #166534); }
        .threat-icon {
            width: 54px;
            height: 54px;
            border-radius: 999px;
            display: grid;
            place-items: center;
            font-size: 1.8rem;
            font-weight: 900;
            background: rgba(255,255,255,0.16);
            border: 1px solid rgba(255,255,255,0.24);
        }
        .threat-status h2 {
            margin: 0;
            font-size: 2.25rem;
            letter-spacing: 0.04em;
            text-transform: uppercase;
        }
        .severity-badge {
            display: inline-flex;
            width: fit-content;
            padding: 6px 10px;
            border-radius: 999px;
            background: rgba(255,255,255,0.16);
            font-weight: 800;
            text-transform: uppercase;
            font-size: 0.78rem;
        }
        .metric-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 12px;
            padding: 20px;
            background: #f8fbff;
        }
        .metric {
            background: #ffffff;
            border: 1px solid var(--line);
            border-radius: 12px;
            padding: 14px;
        }
        .metric-label {
            color: var(--muted);
            font-size: 0.76rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            margin-bottom: 6px;
        }
        .metric-value {
            font-size: 1.24rem;
            font-weight: 850;
            color: #0b1f3a;
            word-break: break-word;
        }
        .evidence-panel {
            padding: 20px;
            display: grid;
            gap: 22px;
        }
        .evidence-block h3 {
            margin: 0 0 10px;
            font-size: 0.92rem;
            color: #0b1f3a;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .primary-evidence {
            width: 100%;
            border-collapse: collapse;
            background: #ffffff;
        }
        .primary-evidence th,
        .primary-evidence td {
            padding: 10px 0;
            border-bottom: 1px solid #e8eef6;
            text-align: left;
            vertical-align: top;
        }
        .primary-evidence th {
            width: 150px;
            color: var(--muted);
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }
        .primary-evidence td {
            color: #0f2747;
            font-weight: 750;
        }
        .url-truncate {
            display: block;
            max-width: 100%;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            cursor: help;
        }
        .indicator-strip {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }
        .risk-badge {
            display: inline-flex;
            align-items: center;
            border-radius: 999px;
            padding: 7px 11px;
            background: #eff6ff;
            color: #1e3a8a;
            border: 1px solid #bfdbfe;
            font-size: 0.84rem;
            font-weight: 800;
        }
        .risk-badge.warn {
            background: #fff7ed;
            color: #9a3412;
            border-color: #fed7aa;
        }
        .evidence-value {
            font-weight: 800;
            color: #0f2747;
            word-break: break-word;
        }
        .summary-list,
        .timeline-list {
            margin: 0;
            padding-left: 18px;
        }
        .summary-list li,
        .timeline-list li {
            margin: 6px 0;
        }
        .summary-content {
            padding: 18px;
        }
        .timeline {
            display: grid;
            gap: 12px;
            padding: 18px;
        }
        .timeline-card {
            display: grid;
            grid-template-columns: 52px minmax(0, 1fr);
            gap: 14px;
            padding: 14px;
            border: 1px solid var(--line);
            border-radius: 12px;
            background: #fbfdff;
        }
        .timeline-num {
            width: 42px;
            height: 42px;
            border-radius: 12px;
            display: grid;
            place-items: center;
            background: #dbeafe;
            color: #1e3a8a;
            font-weight: 900;
        }
        .timeline-card h3 {
            margin: 0 0 6px;
            color: #0b1f3a;
            font-size: 1rem;
        }
        .tag-wrap {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            padding: 18px;
        }
        .mitre-tag {
            border: 1px solid #bfdbfe;
            background: #eff6ff;
            color: #1e3a8a;
            border-radius: 999px;
            padding: 8px 12px;
            font-weight: 800;
        }
        .warning-card {
            display: grid;
            grid-template-columns: 46px minmax(0, 1fr);
            gap: 14px;
            padding: 18px;
            border: 1px solid #fbbf24;
            background: #fffbeb;
            color: #78350f;
            border-radius: 14px;
        }
        .warning-icon {
            width: 42px;
            height: 42px;
            border-radius: 12px;
            display: grid;
            place-items: center;
            background: #f59e0b;
            color: #ffffff;
            font-weight: 900;
            font-size: 1.2rem;
        }
        .tech-details {
            border: 1px solid var(--line);
            border-radius: 14px;
            overflow: hidden;
        }
        .tech-details summary {
            cursor: pointer;
            padding: 16px 18px;
            background: #0b1f3a;
            color: #ffffff;
            font-weight: 850;
        }
        .tech-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 10px;
            padding: 18px;
            background: #f8fbff;
        }
        .tech-item {
            border: 1px solid var(--line);
            border-radius: 10px;
            padding: 10px;
            background: #ffffff;
        }
        .footer {
            border-top: 1px solid var(--line);
            padding: 16px 32px 26px;
            color: var(--muted);
            font-size: 0.86rem;
            text-align: center;
        }
        @media (max-width: 900px) {
            .report-header,
            .threat-card {
                grid-template-columns: 1fr;
            }
            .header-meta {
                min-width: 0;
            }
            .metric-grid,
            .tech-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 620px) {
            .report-page {
                width: 100%;
                margin: 0;
            }
            .report-header,
            .report-body,
            .footer {
                padding-left: 18px;
                padding-right: 18px;
            }
            .metric-grid,
            .tech-grid {
                grid-template-columns: 1fr;
            }
            .primary-evidence th,
            .primary-evidence td {
                display: block;
                width: 100%;
                padding: 6px 0;
            }
            .primary-evidence tr {
                display: block;
                padding: 8px 0;
                border-bottom: 1px solid #e8eef6;
            }
            .primary-evidence th,
            .primary-evidence td {
                border-bottom: none;
            }
            .report-actions {
                justify-content: flex-start;
                flex-wrap: wrap;
            }
        }
        @media print {
            @page {
                size: A4 portrait;
                margin: 8mm;
            }
            * {
                box-shadow: none !important;
                text-shadow: none !important;
            }
            body {
                background: #ffffff;
                color: #0f172a;
                font-size: 10.5px;
                line-height: 1.24;
                print-color-adjust: exact;
                -webkit-print-color-adjust: exact;
            }
            .report-page {
                width: 100%;
                margin: 0;
                border: none;
                box-shadow: none;
            }
            .report-actions,
            .no-print,
            .tech-details,
            .footer,
            .threat-icon {
                display: none !important;
            }
            .report-header {
                display: grid;
                grid-template-columns: 1fr 1.25fr;
                gap: 8px;
                padding: 8px 10px;
                background: #0b1f3a !important;
            }
            .brand-block {
                gap: 8px;
            }
            .brand-block img {
                width: 34px;
                height: 34px;
            }
            .eyebrow {
                font-size: 7px;
                margin-bottom: 1px;
                letter-spacing: 0.08em;
            }
            h1 {
                font-size: 15px;
                line-height: 1.05;
            }
            .header-meta {
                min-width: 0;
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 2px 10px;
                font-size: 8px;
                align-content: center;
            }
            .meta-row {
                border-bottom: none;
                padding-bottom: 0;
                gap: 5px;
            }
            .report-body {
                padding: 8px 0 0;
                gap: 7px;
            }
            .threat-card {
                grid-template-columns: 0.82fr 2fr;
                border-radius: 8px;
                break-inside: avoid;
            }
            .threat-status {
                padding: 9px 10px;
                gap: 4px;
            }
            .threat-status h2 {
                font-size: 15px;
                line-height: 1.05;
            }
            .severity-badge {
                padding: 3px 6px;
                font-size: 7px;
            }
            .metric-grid {
                grid-template-columns: repeat(3, minmax(0, 1fr));
                gap: 4px;
                padding: 7px;
            }
            .metric {
                border-radius: 6px;
                padding: 5px 6px;
            }
            .metric-label {
                font-size: 6.8px;
                margin-bottom: 2px;
                letter-spacing: 0.04em;
            }
            .metric-value {
                font-size: 10px;
                line-height: 1.15;
            }
            .section-card {
                border-radius: 8px;
                break-inside: avoid;
            }
            .section-title {
                padding: 6px 8px;
                font-size: 9.5px;
                letter-spacing: 0.035em;
            }
            .evidence-panel {
                padding: 7px 9px;
                gap: 8px;
            }
            .evidence-block h3 {
                font-size: 8px;
                margin-bottom: 3px;
            }
            .primary-evidence th,
            .primary-evidence td {
                padding: 3px 0;
            }
            .primary-evidence th {
                width: 82px;
                font-size: 7px;
            }
            .primary-evidence td {
                font-size: 9px;
            }
            .indicator-strip {
                gap: 4px;
            }
            .risk-badge {
                padding: 3px 6px;
                font-size: 7.5px;
            }
            .summary-content {
                padding: 7px 9px;
            }
            .summary-list,
            .timeline-list {
                padding-left: 13px;
            }
            .summary-list li,
            .timeline-list li {
                margin: 2px 0;
            }
            .timeline {
                gap: 5px;
                padding: 7px 9px;
            }
            .timeline-card {
                grid-template-columns: 24px minmax(0, 1fr);
                gap: 7px;
                padding: 6px 7px;
                border-radius: 7px;
            }
            .timeline-num {
                width: 20px;
                height: 20px;
                border-radius: 6px;
                font-size: 9px;
            }
            .timeline-card h3 {
                font-size: 9.5px;
                margin: 0 0 2px;
            }
            .tag-wrap {
                gap: 4px;
                padding: 7px 9px;
            }
            .mitre-tag {
                padding: 3px 6px;
                font-size: 7.5px;
            }
            .warning-card {
                grid-template-columns: minmax(0, 1fr);
                gap: 0;
                padding: 7px 9px;
                border-radius: 8px;
                break-inside: avoid;
            }
            .warning-icon {
                display: none;
            }
            .warning-card h2 {
                font-size: 10px !important;
                margin-bottom: 2px !important;
            }
            .warning-card p {
                font-size: 9px;
            }
            .url-truncate {
                max-width: 155mm;
            }
            .section-card,
            .threat-card,
            .warning-card,
            .timeline-card {
                break-inside: avoid;
                page-break-inside: avoid;
            }
            p,
            ul {
                margin-top: 0;
                margin-bottom: 0;
            }
        }
    </style>
</head>

<body>
    <main class="report-page">
        <header class="report-header">
            <div class="brand-block">
                <img src="../img/logo.png" alt="ShieldURL logo">
                <div>
                    <p class="eyebrow">ShieldURL SOC Report</p>
                    <h1>Security Incident Report</h1>
                </div>
            </div>
            <div class="header-meta">
                <div class="meta-row"><span>Case ID</span><strong>#<?php echo h(str_pad((string)$report['id'], 6, '0', STR_PAD_LEFT)); ?></strong></div>
                <div class="meta-row"><span>Generated</span><strong><?php echo h(date('Y-m-d H:i:s')); ?></strong></div>
                <div class="meta-row"><span>Analyzed</span><strong><?php echo h($report['analyzed_at']); ?></strong></div>
                <div class="meta-row"><span>Analyst</span><strong>ShieldURL AI Assistant</strong></div>
                <div class="report-actions">
                    <button class="report-btn" type="button" onclick="window.print()">Print PDF</button>
                    <button class="report-btn primary" type="button" onclick="window.print()">Download PDF</button>
                </div>
            </div>
        </header>

        <section class="report-body">
            <div class="threat-card">
                <div class="threat-status <?php echo h($threatStatusClass); ?>">
                    <div class="threat-icon"><?php echo h(status_icon($threatStatusClass)); ?></div>
                    <div>
                        <p class="eyebrow">Threat Status</p>
                        <h2><?php echo h(strtoupper($displayStatus)); ?></h2>
                    </div>
                    <span class="severity-badge">Severity: <?php echo h($severity); ?></span>
                </div>
                <div class="metric-grid">
                    <div class="metric"><div class="metric-label">Phishing Probability</div><div class="metric-value"><?php echo h(number_format($confidence, 2)); ?>%</div></div>
                    <div class="metric"><div class="metric-label">Risk Level</div><div class="metric-value"><?php echo h(ucfirst((string)$riskLevel)); ?></div></div>
                    <div class="metric"><div class="metric-label">Risk Score</div><div class="metric-value"><?php echo h($riskScore); ?>/10</div></div>
                    <div class="metric"><div class="metric-label">Scan Duration</div><div class="metric-value"><?php echo h(is_numeric($scanDuration) ? $scanDuration . 's' : $scanDuration); ?></div></div>
                    <div class="metric"><div class="metric-label">Detection Engine</div><div class="metric-value"><?php echo h($engine); ?></div></div>
                    <div class="metric"><div class="metric-label">How ShieldURL Decides</div><div class="metric-value"><?php echo h($modelPolicy); ?></div></div>
                </div>
            </div>

            <section class="section-card">
                <h2 class="section-title">Scan Decision Explanation</h2>
                <div class="metric-grid">
                    <div class="metric"><div class="metric-label">Phishing Probability</div><div class="metric-value"><?php echo h(number_format($confidence, 2)); ?>%</div></div>
                    <div class="metric"><div class="metric-label">Detection Sensitivity</div><div class="metric-value"><?php echo h(number_format($selectedThreshold, 2)); ?>%</div></div>
                    <div class="metric"><div class="metric-label">System Detection</div><div class="metric-value"><?php echo h($systemDetection); ?></div></div>
                    <div class="metric"><div class="metric-label">Safety Status</div><div class="metric-value"><?php echo h(strtoupper($displayStatus)); ?></div></div>
                </div>
                <p style="margin: 0.85rem 0 0; color: #475569;">
                    <?php echo h($modelPolicy); ?> Potentially suspicious results show suspicious characteristics, but are not confirmed phishing based on the current evidence. Review the URL carefully before interacting with it.
                </p>
            </section>

            <section class="section-card">
                <h2 class="section-title">URL Evidence</h2>
                <div class="evidence-panel">
                    <div class="evidence-block">
                        <h3>Primary Evidence</h3>
                        <table class="primary-evidence">
                            <tr>
                                <th>Full URL</th>
                                <td><span class="url-truncate" title="<?php echo h($url); ?>"><?php echo h($url); ?></span></td>
                            </tr>
                            <?php if ($domain !== ''): ?>
                                <tr><th>Domain</th><td><?php echo h($domain); ?></td></tr>
                            <?php endif; ?>
                            <tr><th>Protocol</th><td><?php echo h(strtoupper($protocol)); ?></td></tr>
                            <?php if ($tld !== ''): ?>
                                <tr><th>TLD</th><td>.<?php echo h($tld); ?></td></tr>
                            <?php endif; ?>
                            <tr><th>HTTPS Status</th><td><?php echo h($httpsStatus); ?></td></tr>
                        </table>
                    </div>
                    <div class="evidence-block">
                        <h3>Risk Indicators</h3>
                        <div class="indicator-strip">
                            <?php if (!empty($riskIndicators)): ?>
                                <?php foreach ($riskIndicators as $indicator): ?>
                                    <span class="risk-badge warn"><?php echo h($indicator); ?></span>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <span class="risk-badge">No elevated URL indicators</span>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </section>

            <section class="section-card">
                <h2 class="section-title">Incident Summary</h2>
                <div class="summary-content">
                    <p class="metric-label">Executive Summary</p>
                    <ul class="summary-list">
                        <?php foreach (array_slice($executiveSummary, 0, 5) as $summary): ?>
                            <li><?php echo h($summary); ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            </section>

            <section class="section-card">
                <h2 class="section-title">NIST Incident Response Timeline</h2>
                <div class="timeline">
                    <?php foreach ($timeline as $index => $phase): ?>
                        <div class="timeline-card">
                            <div class="timeline-num"><?php echo h($index + 1); ?></div>
                            <div>
                                <h3><?php echo h($phase[0]); ?></h3>
                                <ul class="timeline-list">
                                    <?php foreach (array_slice(normalize_list($phase[2]), 0, 4) as $step): ?>
                                        <li><?php echo h($step); ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </section>

            <section class="section-card">
                <h2 class="section-title">MITRE ATT&CK Mapping</h2>
                <div class="tag-wrap">
                    <?php if (!empty($mitre)): ?>
                        <?php foreach ($mitre as $item): ?>
                            <?php
                            $techId = is_array($item) ? ($item['id'] ?? $item['technique_id'] ?? '') : '';
                            $techName = is_array($item) ? ($item['name'] ?? $item['technique'] ?? $item['description'] ?? '') : (string)$item;
                            ?>
                            <span class="mitre-tag"><?php echo h(trim($techId . ($techId && $techName ? ' → ' : '') . $techName)); ?></span>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <span class="mitre-tag">No ATT&CK technique mapped</span>
                    <?php endif; ?>
                </div>
            </section>

            <section class="warning-card">
                <div class="warning-icon">!</div>
                <div>
                    <h2 style="margin: 0 0 6px; font-size: 1.08rem;">User Advisory</h2>
                    <p style="margin: 0;"><?php echo h($userAdvisory); ?></p>
                </div>
            </section>

            <details class="tech-details">
                <summary>View Technical Analysis</summary>
                <div class="tech-grid">
                    <?php if (!empty($features)): ?>
                        <?php foreach ($features as $key => $value): ?>
                            <div class="tech-item">
                                <div class="metric-label"><?php echo h(feature_label($key)); ?></div>
                                <div class="evidence-value"><?php echo h(display_feature_value($value)); ?></div>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div class="tech-item">
                            <div class="metric-label">Technical Features</div>
                            <div class="evidence-value">No feature extraction data available.</div>
                        </div>
                    <?php endif; ?>
                </div>
            </details>
        </section>

        <footer class="footer">
            Generated by ShieldURL Automated Response System. Debug output, stack traces, and runtime warnings are suppressed from this report.
        </footer>
    </main>
    <script>
        window.addEventListener('beforeprint', () => {
            document.querySelectorAll('details.tech-details').forEach(details => details.open = true);
        });
    </script>
</body>

</html>
