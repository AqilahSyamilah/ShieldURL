<?php
require_once '../config/db.php';
require_once '../shared/verdict_report.php';

header('Content-Type: application/json');

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit();
}

$id = isset($_GET['id']) ? (int) $_GET['id'] : 0;
if ($id <= 0) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid report id']);
    exit();
}

$db = new Database();
$conn = $db->getConnection();

$isAdmin = isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
if ($isAdmin) {
    $stmt = $conn->prepare('
        SELECT l.*, u.username
        FROM url_logs l
        LEFT JOIN users u ON l.user_id = u.id
        WHERE l.id = ?
    ');
    $stmt->execute([$id]);
} else {
    $stmt = $conn->prepare('
        SELECT l.*, u.username
        FROM url_logs l
        LEFT JOIN users u ON l.user_id = u.id
        WHERE l.id = ? AND l.user_id = ?
    ');
    $stmt->execute([$id, $_SESSION['user_id']]);
}

$report = $stmt->fetch(PDO::FETCH_ASSOC);
if (!$report) {
    http_response_code(404);
    echo json_encode(['error' => 'Report not found']);
    exit();
}

$safeDecode = function ($value, $fallback) {
    if ($value === null || $value === '') {
        return $fallback;
    }
    $decoded = json_decode($value, true);
    return json_last_error() === JSON_ERROR_NONE ? $decoded : $fallback;
};

$analysis = $safeDecode($report['analysis_result'] ?? '', []);
$reportAudience = (isset($_SESSION['role']) && $_SESSION['role'] === 'admin') ? 'admin' : 'user';
$llmReport = shield_apply_verdict_report($analysis, $report, $analysis['llm_report'] ?? [], $reportAudience);
$scanDuration = $analysis['debug']['php_total_seconds'] ?? $analysis['debug']['curl_total_seconds'] ?? null;

$auditStmt = $conn->prepare("
    SELECT ip_address, country
    FROM audit_logs
    WHERE user_id = ? AND activity_type = 'url_scan' AND activity_details LIKE ?
    ORDER BY ABS(TIMESTAMPDIFF(SECOND, timestamp, ?)) ASC
    LIMIT 1
");
$auditStmt->execute([
    $report['user_id'],
    '%' . $report['url'] . '%',
    $report['analyzed_at']
]);
$audit = $auditStmt->fetch(PDO::FETCH_ASSOC) ?: [];

echo json_encode([
    'id' => (int) $report['id'],
    'user_id' => (int) $report['user_id'],
    'username' => $report['username'] ?? '',
    'url' => $report['url'],
    'status' => $analysis['status'] ?? $report['status'],
    'display_status' => $analysis['display_status'] ?? ($analysis['overall']['display_verdict'] ?? $report['status']),
    'confidence_score' => (float)($analysis['phishing_probability'] ?? ($analysis['confidence_score'] ?? $report['confidence_score'])),
    'phishing_probability' => (float)($analysis['phishing_probability'] ?? ($analysis['ml']['phishing_probability'] ?? $report['confidence_score'])),
    'selected_threshold' => (float)($analysis['selected_threshold'] ?? ($analysis['ml']['selected_threshold'] ?? 0.5)),
    'model_policy' => $analysis['model_policy'] ?? ($llmReport['model_policy'] ?? shield_dynamic_policy_text($llmReport['verdict_category'] ?? 'safe')),
    'risk_level' => $analysis['risk_level'] ?? ($report['risk_level'] ?? ''),
    'user_interaction_status' => $analysis['user_interaction_status'] ?? ($llmReport['user_interaction_status'] ?? 'Not collected'),
    'report_audience' => $reportAudience,
    'analyzed_at' => $report['analyzed_at'],
    'scan_duration' => $scanDuration,
    'detection_engine' => 'ShieldURL ML + LLM Incident Response',
    'ip_address' => $audit['ip_address'] ?? '',
    'country' => $audit['country'] ?? '',
    'llm_report' => $llmReport,
    'llm_summary' => $llmReport['incident_summary'] ?? ($report['llm_summary'] ?? ''),
    'features' => $safeDecode($report['features'] ?? '', new stdClass()),
    'incident_response' => $llmReport['eradication_recovery_actions'] ?? [],
    'nist_response' => $llmReport['containment_actions'] ?? [],
    'post_incident_recommendations' => $llmReport['post_incident_recommendations'] ?? [],
    'mitre_attack' => $llmReport['mitre_attack_mapping'] ?? [],
    'user_advisory' => $llmReport['user_advisory'] ?? ($report['user_advisory_text'] ?? ''),
]);
?>
