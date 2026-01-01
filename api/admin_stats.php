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

// Recent activity count
$stmt = $conn->query("SELECT COUNT(*) as count FROM user_activity WHERE created_at >= NOW() - INTERVAL 7 DAY");
$stats['recent_activity'] = $stmt->fetch()['count'];

echo json_encode($stats);
?>