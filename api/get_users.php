<?php
require_once '../config/db.php';
header('Content-Type: application/json');

if (!isset($_SESSION['user_id']) || ($_SESSION['role'] ?? '') !== 'admin') {
    echo json_encode([]);
    exit();
}

$db = new Database();
$conn = $db->getConnection();

$stmt = $conn->prepare("
    SELECT 
        id, full_name, username, email, phone,
        department, role, is_active,
        DATE_FORMAT(registered_at, '%Y-%m-%d %H:%i:%s') AS registered_at,
        DATE_FORMAT(last_login, '%Y-%m-%d %H:%i:%s') AS last_login
    FROM users
    ORDER BY registered_at DESC
");
$stmt->execute();

echo json_encode($stmt->fetchAll());
