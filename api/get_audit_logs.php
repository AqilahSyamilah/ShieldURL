<?php
require_once '../config/db.php';

header('Content-Type: application/json');

if (!isset($_SESSION['user_id']) || ($_SESSION['role'] ?? '') !== 'admin') {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit();
}

$db = new Database();
$conn = $db->getConnection();

$where = [];
$params = [];

$search = trim($_GET['search'] ?? '');
if ($search !== '') {
    $where[] = "(username LIKE ? OR activity_details LIKE ? OR ip_address LIKE ? OR session_id LIKE ?)";
    $like = '%' . $search . '%';
    array_push($params, $like, $like, $like, $like);
}

$activity = trim($_GET['activity'] ?? '');
if ($activity !== '') {
    $where[] = "activity_type = ?";
    $params[] = $activity;
}

$division = trim($_GET['division'] ?? '');
if ($division !== '') {
    $where[] = "division = ?";
    $params[] = $division;
}

$country = trim($_GET['country'] ?? '');
if ($country !== '') {
    $where[] = "country = ?";
    $params[] = $country;
}

$status = trim($_GET['status'] ?? '');
if ($status !== '') {
    $where[] = "status = ?";
    $params[] = $status;
}

$dateFrom = trim($_GET['date_from'] ?? '');
if ($dateFrom !== '') {
    $where[] = "timestamp >= ?";
    $params[] = $dateFrom . ' 00:00:00';
}

$dateTo = trim($_GET['date_to'] ?? '');
if ($dateTo !== '') {
    $where[] = "timestamp <= ?";
    $params[] = $dateTo . ' 23:59:59';
}

$sql = "
    SELECT id, DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i:%s') AS timestamp, user_id, username, role,
           division, activity_type, activity_details, ip_address, country, status, session_id
    FROM audit_logs
";
if ($where) {
    $sql .= ' WHERE ' . implode(' AND ', $where);
}
$sql .= ' ORDER BY timestamp DESC LIMIT 300';

$stmt = $conn->prepare($sql);
$stmt->execute($params);
$logs = $stmt->fetchAll();

$activities = $conn->query("SELECT DISTINCT activity_type FROM audit_logs ORDER BY activity_type")->fetchAll(PDO::FETCH_COLUMN);
$divisions = $conn->query("SELECT DISTINCT division FROM audit_logs WHERE division IS NOT NULL AND division <> '' ORDER BY division")->fetchAll(PDO::FETCH_COLUMN);
$countries = $conn->query("SELECT DISTINCT country FROM audit_logs WHERE country IS NOT NULL AND country <> '' ORDER BY country")->fetchAll(PDO::FETCH_COLUMN);

echo json_encode([
    'success' => true,
    'logs' => $logs,
    'filters' => [
        'activities' => $activities,
        'divisions' => $divisions,
        'countries' => $countries,
    ],
]);
