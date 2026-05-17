<?php
require_once '../config/db.php';

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
    'status' => $report['status'],
    'confidence_score' => (float) $report['confidence_score'],
    'risk_level' => $report['risk_level'] ?? '',
    'analyzed_at' => $report['analyzed_at'],
    'scan_duration' => $scanDuration,
    'detection_engine' => 'ShieldURL ML + LLM Incident Response',
    'ip_address' => $audit['ip_address'] ?? '',
    'country' => $audit['country'] ?? '',
    'llm_summary' => $report['llm_summary'] ?? '',
    'features' => $safeDecode($report['features'] ?? '', new stdClass()),
    'incident_response' => $safeDecode($report['incident_response_text'] ?? '', []),
    'nist_response' => $safeDecode($report['nist_response_json'] ?? '', []),
    'mitre_attack' => $safeDecode($report['mitre_attack_json'] ?? '', []),
    'user_advisory' => $report['user_advisory_text'] ?? '',
]);
?>
