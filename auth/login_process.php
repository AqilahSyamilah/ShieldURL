<?php
require_once '../config/db.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: login.php?err=Invalid request");
    exit();
}

$username = trim($_POST['username'] ?? '');
$password = $_POST['password'] ?? '';

if ($username === '' || $password === '') {
    header("Location: login.php?err=Missing username or password");
    exit();
}

$db = new Database();
$conn = $db->getConnection();

$stmt = $conn->prepare("SELECT * FROM users WHERE username=? AND is_active=TRUE LIMIT 1");
$stmt->execute([$username]);
$user = $stmt->fetch();

if (!$user) {
    header("Location: login.php?err=User not found");
    exit();
}

if (!password_verify($password, $user['password'])) {
    header("Location: login.php?err=Invalid password");
    exit();
}

$_SESSION['user_id'] = $user['id'];
$_SESSION['username'] = $user['username'];
$_SESSION['role'] = $user['role'];

$conn->prepare("UPDATE users SET last_login=NOW() WHERE id=?")->execute([$user['id']]);

if ($user['role'] === 'admin') {
    header("Location: ../admin/index.php");
} else {
    header("Location: ../index.php");
}
exit();
