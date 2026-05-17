<?php
require_once '../config/db.php';
require_once '../shared/audit.php';

header('Content-Type: application/json');

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit();
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Invalid request method']);
    exit();
}

$input = json_decode(file_get_contents('php://input'), true) ?: [];
$activityType = $input['activity_type'] ?? '';
$allowed = ['settings_update'];

if (!in_array($activityType, $allowed, true)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Unsupported activity type']);
    exit();
}

$details = trim((string)($input['activity_details'] ?? ''));

$db = new Database();
$conn = $db->getConnection();
audit_log($conn, $activityType, $details ?: 'Settings updated', 'success');

echo json_encode(['success' => true]);
