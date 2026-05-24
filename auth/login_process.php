<?php
require_once '../config/db.php';
require_once '../shared/audit.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: login.php?err=Invalid request");
    exit();
}

$username = trim($_POST['username'] ?? '');
$password = $_POST['password'] ?? '';

if ($username === '' || $password === '') {
    $db = new Database();
    $conn = $db->getConnection();
    audit_log($conn, 'login_failed', 'Missing username or password', 'failed', ['username' => $username ?: 'unknown']);
    header("Location: login.php?err=Missing username or password");
    exit();
}

$db = new Database();
$conn = $db->getConnection();

$stmt = $conn->prepare("SELECT * FROM users WHERE (username=? OR email=?) AND is_active=TRUE LIMIT 1");
$stmt->execute([$username, $username]);
$user = $stmt->fetch();

if (!$user) {
    audit_log($conn, 'login_failed', "Login failed for '{$username}': user not found", 'failed', ['username' => $username]);
    header("Location: login.php?err=User not found");
    exit();
}

if (!password_verify($password, $user['password'])) {
    audit_log($conn, 'login_failed', "Login failed for '{$username}': invalid password", 'failed', [
        'user_id' => $user['id'],
        'username' => $user['username'],
        'role' => $user['role'],
        'division' => $user['department'] ?? null,
    ]);
    header("Location: login.php?err=Invalid password");
    exit();
}

$_SESSION['user_id'] = $user['id'];
$_SESSION['username'] = $user['username'];
$_SESSION['role'] = $user['role'];
$_SESSION['force_password_change'] = (bool)($user['force_password_change'] ?? false);
$_SESSION['mfa_required'] = (bool)($user['mfa_required'] ?? false);
$_SESSION['mfa_configured'] = (bool)($user['mfa_configured'] ?? false);

$conn->prepare("UPDATE users SET last_login=NOW() WHERE id=?")->execute([$user['id']]);
audit_log($conn, 'login_success', 'User logged in successfully', 'success');

if ($_SESSION['force_password_change']) {
    header("Location: change_password.php?first_login=1");
    exit();
}

if ($_SESSION['mfa_required'] && !$_SESSION['mfa_configured']) {
    header("Location: mfa_setup.php");
    exit();
}

if ($user['role'] === 'admin') {
    header("Location: ../admin/index.php?transition=1");
} else {
    header("Location: ../index.php?transition=1");
}
exit();
