<?php
require_once '../config/db.php';
require_once '../shared/verdict_report.php';

header('Content-Type: application/json');

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'error' => 'Not authenticated']);
    exit();
}

$data = json_decode(file_get_contents('php://input'), true);
$analysis = is_array($data['analysis_result'] ?? null) ? $data['analysis_result'] : [];
$analysis['url'] = $data['url'] ?? ($analysis['url'] ?? '');
$analysis['status'] = $data['status'] ?? ($analysis['status'] ?? 'safe');
$analysis['confidence_score'] = shield_unit_probability($data['phishing_probability'] ?? ($data['confidence_score'] ?? ($analysis['phishing_probability'] ?? ($analysis['confidence_score'] ?? 0))));
$reportAudience = ($_SESSION['role'] ?? '') === 'admin' ? 'admin' : 'user';
shield_apply_verdict_report($analysis, [], [], $reportAudience);

$db = new Database();
$conn = $db->getConnection();

$stmt = $conn->prepare("
    INSERT INTO url_logs (user_id, url, status, confidence_score, features, analysis_result) 
    VALUES (:user_id, :url, :status, :confidence, :features, :result)
");

$stmt->execute([
    ':user_id' => $_SESSION['user_id'],
    ':url' => $data['url'],
    ':status' => $analysis['status'],
    ':confidence' => $analysis['phishing_probability'],
    ':features' => json_encode($data['features']),
    ':result' => json_encode($analysis)
]);

echo json_encode(['success' => true]);
?>
