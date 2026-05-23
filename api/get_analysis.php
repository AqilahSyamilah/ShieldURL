<?php
require_once '../config/db.php';
require_once '../shared/verdict_report.php';

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
        SELECT l.id, l.url, l.status, l.confidence_score, l.analyzed_at, l.analysis_result, u.username
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
        SELECT id, url, status, confidence_score, analyzed_at, analysis_result, 'Me' as username
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
foreach ($results as &$row) {
    $analysis = json_decode($row['analysis_result'] ?? '', true);
    if (json_last_error() === JSON_ERROR_NONE && is_array($analysis)) {
        $probability = shield_unit_probability($analysis['phishing_probability'] ?? ($analysis['ml']['phishing_probability'] ?? $row['confidence_score']));
        $threshold = shield_unit_probability($analysis['selected_threshold'] ?? ($analysis['ml']['selected_threshold'] ?? ($analysis['detection']['lexical_threshold'] ?? 0.5)));
        $category = shield_verdict_category($analysis['status'] ?? $row['status'], $analysis['display_status'] ?? ($analysis['overall']['display_verdict'] ?? ''), $analysis['risk_level'] ?? '', $probability, $threshold);
        $row['status'] = $category === 'phishing' ? 'phishing' : ($category === 'suspicious' ? 'suspicious' : 'safe');
        $row['display_status'] = shield_display_status($category, $analysis['display_status'] ?? ($analysis['overall']['display_verdict'] ?? $row['status']));
        $row['confidence_score'] = $probability;
    } else {
        $row['display_status'] = $row['status'];
        $row['confidence_score'] = shield_unit_probability($row['confidence_score']);
    }
    unset($row['analysis_result']);
}
echo json_encode($results);
?>
