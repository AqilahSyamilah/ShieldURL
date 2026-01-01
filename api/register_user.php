<?php
require_once '../config/db.php';
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'Invalid request method']);
    exit();
}

if (!isset($_SESSION['user_id']) || ($_SESSION['role'] ?? '') !== 'admin') {
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit();
}

$input = json_decode(file_get_contents('php://input'), true) ?? [];

$required = ['full_name','username','email','password','role'];
foreach ($required as $field) {
    if (empty($input[$field])) {
        echo json_encode(['success' => false, 'error' => "Field '$field' is required"]);
        exit();
    }
}

if (!filter_var($input['email'], FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['success' => false, 'error' => 'Invalid email']);
    exit();
}

if (!preg_match('/^[a-zA-Z0-9_]+$/', $input['username'])) {
    echo json_encode(['success' => false, 'error' => 'Username can only contain letters, numbers, underscores']);
    exit();
}

if (!in_array($input['role'], ['admin','user'], true)) {
    echo json_encode(['success' => false, 'error' => 'Invalid role']);
    exit();
}

$db = new Database();
$conn = $db->getConnection();

$check = $conn->prepare("SELECT id FROM users WHERE username=? OR email=? LIMIT 1");
$check->execute([$input['username'], $input['email']]);
if ($check->fetch()) {
    echo json_encode(['success' => false, 'error' => 'Username or email already exists']);
    exit();
}

$hashed = password_hash($input['password'], PASSWORD_DEFAULT);

try {
    $stmt = $conn->prepare("
        INSERT INTO users (full_name, username, email, phone, department, role, password, is_active, registered_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, TRUE, NOW())
    ");

    $stmt->execute([
        $input['full_name'],
        $input['username'],
        $input['email'],
        $input['phone'] ?? null,
        $input['department'] ?? null,
        $input['role'],
        $hashed
    ]);

    $newId = $conn->lastInsertId();

    $activity = $conn->prepare("
        INSERT INTO user_activity (user_id, activity_type, description, ip_address)
        VALUES (?, 'user_registration', ?, ?)
    ");
    $desc = "Admin '{$_SESSION['username']}' registered new user '{$input['username']}'";
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    $activity->execute([$_SESSION['user_id'], $desc, $ip]);

    echo json_encode(['success' => true, 'message' => 'User registered successfully!', 'user_id' => $newId]);
} catch (PDOException $e) {
    echo json_encode(['success' => false, 'error' => 'Database error: ' . $e->getMessage()]);
}
