<?php
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);

require_once '../config/db.php';
require_once '../shared/audit.php';

header('Content-Type: application/json');

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

function respond_password_json($payload, $statusCode = 200)
{
    http_response_code($statusCode);
    echo json_encode($payload);
    exit();
}

function password_strength_error($password)
{
    if (strlen($password) < 8) {
        return 'New password must be at least 8 characters.';
    }
    if (!preg_match('/[0-9]/', $password) || !preg_match('/[^A-Za-z0-9]/', $password)) {
        return 'New password must include at least one number and one symbol.';
    }
    return '';
}

if (!isset($_SESSION['user_id'])) {
    respond_password_json(['success' => false, 'message' => 'Not authenticated'], 401);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond_password_json(['success' => false, 'message' => 'Method not allowed'], 405);
}

$data = json_decode(file_get_contents('php://input'), true);
if (!is_array($data)) {
    respond_password_json(['success' => false, 'message' => 'Invalid request body'], 400);
}

$currentPassword = (string)($data['current_password'] ?? '');
$newPassword = (string)($data['new_password'] ?? '');
$confirmPassword = (string)($data['confirm_password'] ?? '');

if ($currentPassword === '' || $newPassword === '' || $confirmPassword === '') {
    respond_password_json(['success' => false, 'message' => 'Please complete all password fields.'], 400);
}

if ($newPassword !== $confirmPassword) {
    respond_password_json(['success' => false, 'message' => 'Confirm password must match the new password.'], 400);
}

if ($error = password_strength_error($newPassword)) {
    respond_password_json(['success' => false, 'message' => $error], 400);
}

try {
    $db = new Database();
    $conn = $db->getConnection();

    $stmt = $conn->prepare("SELECT password FROM users WHERE id = ? AND is_active = TRUE LIMIT 1");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        respond_password_json(['success' => false, 'message' => 'User account was not found.'], 404);
    }

    if (!password_verify($currentPassword, $user['password'])) {
        audit_log($conn, 'password_change', 'Password change failed: incorrect current password', 'failed');
        respond_password_json(['success' => false, 'message' => 'Current password is incorrect.'], 400);
    }

    if (password_verify($newPassword, $user['password'])) {
        respond_password_json(['success' => false, 'message' => 'New password must be different from the current password.'], 400);
    }

    $hashed = password_hash($newPassword, PASSWORD_DEFAULT);
    $update = $conn->prepare("UPDATE users SET password = ?, force_password_change = FALSE, account_status = 'active' WHERE id = ?");
    $update->execute([$hashed, $_SESSION['user_id']]);
    $_SESSION['force_password_change'] = false;

    audit_log($conn, 'password_change', 'Password changed successfully from settings', 'success');
    respond_password_json(['success' => true, 'message' => 'Your password has been changed successfully.']);
} catch (Exception $e) {
    if (isset($conn)) {
        audit_log($conn, 'password_change', 'Password change failed: ' . $e->getMessage(), 'failed');
    }
    respond_password_json(['success' => false, 'message' => 'Unable to update password right now.'], 500);
}
?>
