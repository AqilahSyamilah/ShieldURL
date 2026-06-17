<?php
require_once '../config/db.php';

header('Content-Type: application/json');

// Check if admin is logged in
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    echo json_encode([]);
    exit();
}

$db = new Database();
$conn = $db->getConnection();

$stats = [];

// Total users
$stmt = $conn->query("SELECT COUNT(*) as count FROM users");
$stats['total_users'] = $stmt->fetch()['count'];

// Active users
$stmt = $conn->query("SELECT COUNT(*) as count FROM users WHERE is_active = TRUE");
$stats['active_users'] = $stmt->fetch()['count'];

// Total URL analyses
$stmt = $conn->query("SELECT COUNT(*) as count FROM url_logs");
$stats['total_analyses'] = $stmt->fetch()['count'];

// Detection totals by verdict
$stmt = $conn->query("
    SELECT
        SUM(CASE WHEN status = 'safe' THEN 1 ELSE 0 END) AS safe_count,
        SUM(CASE WHEN status = 'suspicious' THEN 1 ELSE 0 END) AS suspicious_count,
        SUM(CASE WHEN status = 'phishing' THEN 1 ELSE 0 END) AS phishing_count
    FROM url_logs
");
$detectionStats = $stmt->fetch() ?: [];
$stats['safe_detections'] = (int)($detectionStats['safe_count'] ?? 0);
$stats['suspicious_detections'] = (int)($detectionStats['suspicious_count'] ?? 0);
$stats['phishing_detections'] = (int)($detectionStats['phishing_count'] ?? 0);
$stats['detection_counts'] = [
    'safe' => $stats['safe_detections'],
    'suspicious' => $stats['suspicious_detections'],
    'phishing' => $stats['phishing_detections'],
];

// Recent activity count
$stmt = $conn->query("SELECT COUNT(*) as count FROM user_activity WHERE created_at >= NOW() - INTERVAL 7 DAY");
$stats['recent_activity'] = $stmt->fetch()['count'];

echo json_encode($stats);
?>
