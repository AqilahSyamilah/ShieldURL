<?php
require_once '../config/db.php';

header('Content-Type: application/json');

if (!isset($_SESSION['user_id'])) {
    echo json_encode([]);
    exit();
}

$db = new Database();
$conn = $db->getConnection();

// Check if admin
$isAdmin = isset($_SESSION['role']) && $_SESSION['role'] === 'admin';

if ($isAdmin) {
    // Admin sees all history with usernames
    $stmt = $conn->prepare("
        SELECT l.id, l.url, l.status, l.confidence_score, l.analyzed_at, u.username 
        FROM url_logs l
        JOIN users u ON l.user_id = u.id
        ORDER BY l.analyzed_at DESC 
        LIMIT 50
    ");
    $stmt->execute();
} else {
    // User sees only their history
    $stmt = $conn->prepare("
        SELECT id, url, status, confidence_score, analyzed_at, 'Me' as username
        FROM url_logs 
        WHERE user_id = :user_id 
        ORDER BY analyzed_at DESC 
        LIMIT 10
    ");
    $stmt->execute([':user_id' => $_SESSION['user_id']]);
}

$results = $stmt->fetchAll(PDO::FETCH_ASSOC);

echo json_encode($results);
?>