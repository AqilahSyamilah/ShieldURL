<?php
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);
ini_set('max_execution_time', '120');
set_time_limit(120);

require_once '../config/db.php';

header('Content-Type: application/json');

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'message' => 'Not authenticated']);
    exit();
}

function respond_json($payload, $statusCode = 200)
{
    http_response_code($statusCode);
    echo json_encode($payload);
    exit();
}

function safe_decode_report($value)
{
    if (!is_string($value) || trim($value) === '') {
        return [];
    }
    $decoded = json_decode($value, true);
    return is_array($decoded) ? $decoded : [];
}

$data = json_decode(file_get_contents('php://input'), true);
$reportId = intval($data['report_id'] ?? 0);
if ($reportId <= 0) {
    respond_json(['success' => false, 'message' => 'Missing report_id'], 400);
}

$started = microtime(true);
$db = new Database();
$conn = $db->getConnection();

$isAdmin = isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
if ($isAdmin) {
    $stmt = $conn->prepare('SELECT * FROM url_logs WHERE id = ? LIMIT 1');
    $stmt->execute([$reportId]);
} else {
    $stmt = $conn->prepare('SELECT * FROM url_logs WHERE id = ? AND user_id = ? LIMIT 1');
    $stmt->execute([$reportId, $_SESSION['user_id']]);
}
$row = $stmt->fetch(PDO::FETCH_ASSOC);
if (!$row) {
    respond_json(['success' => false, 'message' => 'Report not found'], 404);
}

$analysis = safe_decode_report($row['analysis_result'] ?? '');
$existingReport = $analysis['llm_report'] ?? [];
if (is_array($existingReport) && !empty($existingReport) && (($existingReport['status'] ?? '') !== 'pending')) {
    respond_json([
        'success' => true,
        'cache_used' => true,
        'llm_pending' => false,
        'llm_report' => $existingReport,
        'llm' => $existingReport,
        'llm_summary' => $existingReport['incident_summary'] ?? '',
        'mitre_techniques' => $existingReport['mitre_attack_mapping'] ?? [],
        'nist_response' => $existingReport['containment_actions'] ?? [],
        'incident_response' => $existingReport['eradication_recovery_actions'] ?? [],
        'user_advisory' => $existingReport['user_advisory'] ?? '',
        'timing' => [
            'detection_seconds' => 0,
            'llm_seconds' => 0,
            'total_seconds' => round(microtime(true) - $started, 3),
            'cache_used' => true,
            'fallback_used' => false,
        ],
    ]);
}

$payload = json_encode([
    'url' => $row['url'],
    'clicked' => $analysis['clicked'] ?? null,
    'verdict' => $analysis['display_status'] ?? ($analysis['overall']['display_verdict'] ?? $row['status']),
    'confidence' => floatval($analysis['phishing_probability'] ?? $row['confidence_score']),
    'risk' => $row['risk_level'] ?? ($analysis['risk_level'] ?? 'low'),
]);

if (!function_exists('curl_init')) {
    respond_json(['success' => false, 'message' => 'PHP cURL extension is not enabled.'], 503);
}

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'http://127.0.0.1:8000/llm_report');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json', 'Accept: application/json']);
curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
curl_setopt($ch, CURLOPT_TIMEOUT, 100);
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curlErr = curl_error($ch);
curl_close($ch);

$api = is_string($response) ? json_decode($response, true) : null;
if (!is_array($api) || $httpCode < 200 || $httpCode >= 300) {
    respond_json([
        'success' => false,
        'message' => 'AI report generation failed',
        'http_code' => $httpCode,
        'curl_error' => $curlErr,
    ], 502);
}

$llmReport = $api['llm_report'] ?? ($api['llm'] ?? []);
if (!is_array($llmReport)) {
    $llmReport = [];
}

$analysis['llm_report'] = $llmReport;
$analysis['llm'] = $llmReport;
$analysis['llm_pending'] = false;
$analysis['cache_used'] = false;
$analysis['timing']['llm_seconds'] = $api['timing']['llm_seconds'] ?? null;
$analysis['timing']['total_seconds'] = ($analysis['timing']['detection_seconds'] ?? 0) + ($api['timing']['llm_seconds'] ?? 0);
$analysis['timing']['cache_used'] = false;
$analysis['timing']['fallback_used'] = $api['timing']['fallback_used'] ?? false;

$update = $conn->prepare('
    UPDATE url_logs
    SET llm_summary = ?, mitre_attack_json = ?, nist_response_json = ?, incident_response_text = ?, user_advisory_text = ?, analysis_result = ?
    WHERE id = ?
');
$update->execute([
    $llmReport['incident_summary'] ?? '',
    json_encode($llmReport['mitre_attack_mapping'] ?? []),
    json_encode($llmReport['containment_actions'] ?? []),
    json_encode($llmReport['eradication_recovery_actions'] ?? []),
    $llmReport['user_advisory'] ?? '',
    json_encode($analysis),
    $reportId,
]);

respond_json([
    'success' => true,
    'cache_used' => false,
    'llm_pending' => false,
    'llm_report' => $llmReport,
    'llm' => $llmReport,
    'llm_summary' => $llmReport['incident_summary'] ?? '',
    'mitre_techniques' => $llmReport['mitre_attack_mapping'] ?? [],
    'nist_response' => $llmReport['containment_actions'] ?? [],
    'incident_response' => $llmReport['eradication_recovery_actions'] ?? [],
    'user_advisory' => $llmReport['user_advisory'] ?? '',
    'timing' => $analysis['timing'] ?? [],
]);
?>
