<?php
require_once '../config/db.php';

header('Content-Type: application/json');

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'error' => 'Not authenticated']);
    exit();
}

$data = json_decode(file_get_contents('php://input'), true);

$db = new Database();
$conn = $db->getConnection();

$stmt = $conn->prepare("
    INSERT INTO url_logs (user_id, url, status, confidence_score, features, analysis_result) 
    VALUES (:user_id, :url, :status, :confidence, :features, :result)
");

$stmt->execute([
    ':user_id' => $_SESSION['user_id'],
    ':url' => $data['url'],
    ':status' => $data['status'],
    ':confidence' => $data['confidence_score'],
    ':features' => json_encode($data['features']),
    ':result' => json_encode($data['analysis_result'])
]);

echo json_encode(['success' => true]);
?>