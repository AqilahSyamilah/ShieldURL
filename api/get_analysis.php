<?php
require_once '../config/db.php';

header('Content-Type: application/json');

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id'])) {
    echo json_encode([]);
    exit();
}

$db = new Database();
$conn = $db->getConnection();

$filter = isset($_GET['filter']) ? strtolower(trim($_GET['filter'])) : '';
$allowedFilters = ['safe', 'phishing', 'suspicious'];
if (!in_array($filter, $allowedFilters, true)) {
    $filter = '';
}

$isAdmin = isset($_SESSION['role']) && $_SESSION['role'] === 'admin';

if ($isAdmin) {
    $sql = "
        SELECT l.id, l.url, l.status, l.confidence_score, l.analyzed_at, u.username
        FROM url_logs l
        JOIN users u ON l.user_id = u.id
    ";
    $params = [];

    if ($filter !== '') {
        $sql .= " WHERE l.status = :filter";
        $params[':filter'] = $filter;
    }

    $sql .= " ORDER BY l.analyzed_at DESC";
    $stmt = $conn->prepare($sql);
    $stmt->execute($params);
} else {
    $sql = "
        SELECT id, url, status, confidence_score, analyzed_at, 'Me' as username
        FROM url_logs
        WHERE user_id = :user_id
    ";
    $params = [':user_id' => $_SESSION['user_id']];

    if ($filter !== '') {
        $sql .= " AND status = :filter";
        $params[':filter'] = $filter;
    }

    $sql .= " ORDER BY analyzed_at DESC";
    $stmt = $conn->prepare($sql);
    $stmt->execute($params);
}

$results = $stmt->fetchAll(PDO::FETCH_ASSOC);
echo json_encode($results);
?>
