<?php
require_once '../config/db.php';
require_once '../shared/audit.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$db = new Database();
$conn = $db->getConnection();
$message = '';
$messageType = '';

$stmt = $conn->prepare("SELECT id, password, role, force_password_change, mfa_required, mfa_configured FROM users WHERE id=? AND is_active=TRUE LIMIT 1");
$stmt->execute([$_SESSION['user_id']]);
$user = $stmt->fetch();

if (!$user) {
    session_destroy();
    header("Location: login.php?err=User not found");
    exit();
}

if (empty($user['force_password_change'])) {
    if (!empty($user['mfa_required']) && empty($user['mfa_configured'])) {
        header("Location: mfa_setup.php");
    } elseif (($_SESSION['role'] ?? $user['role']) === 'admin') {
        header("Location: ../admin/index.php");
    } else {
        header("Location: ../index.php");
    }
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

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $currentPassword = $_POST['current_password'] ?? '';
    $newPassword = $_POST['new_password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';

    if ($currentPassword === '' || $newPassword === '' || $confirmPassword === '') {
        $message = 'Please complete all password fields.';
        $messageType = 'error';
    } elseif (!password_verify($currentPassword, $user['password'])) {
        $message = 'Current temporary password is incorrect.';
        $messageType = 'error';
    } elseif ($newPassword !== $confirmPassword) {
        $message = 'Confirm password must match the new password.';
        $messageType = 'error';
    } elseif (password_verify($newPassword, $user['password'])) {
        $message = 'New password must be different from the temporary password.';
        $messageType = 'error';
    } elseif ($error = password_strength_error($newPassword)) {
        $message = $error;
        $messageType = 'error';
    } else {
        $hashed = password_hash($newPassword, PASSWORD_DEFAULT);
        $update = $conn->prepare("UPDATE users SET password=?, force_password_change=FALSE, account_status='active' WHERE id=?");
        $update->execute([$hashed, $_SESSION['user_id']]);
        $_SESSION['force_password_change'] = false;
        audit_log($conn, 'password_change', 'Password changed successfully', 'success');
        if (!empty($user['mfa_required']) && empty($user['mfa_configured'])) {
            header("Location: mfa_setup.php?password_changed=1");
        } elseif (($_SESSION['role'] ?? $user['role']) === 'admin') {
            header("Location: ../admin/index.php?transition=1");
        } else {
            header("Location: ../index.php?transition=1");
        }
        exit();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Change Password - ShieldURL</title>
  <style>
    * { box-sizing: border-box; }
    body { margin: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
    .auth-wrapper {
      min-height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      background: radial-gradient(circle at top, #eef2ff 0%, #f8fafc 45%, #fdf7ec 100%);
      padding: 1rem;
    }
    .auth-box {
      width: 100%;
      max-width: 460px;
      background: #ffffff;
      padding: 2.5rem;
      border-radius: 15px;
      box-shadow: 0 15px 60px rgba(11, 31, 58, 0.22);
      border: 1px solid rgba(203, 213, 225, 0.75);
    }
    h1 { margin: 0 0 0.5rem; color: #0b1f3a; }
    p { margin: 0 0 1.5rem; color: #64748b; line-height: 1.5; }
    .form-group { margin-bottom: 1.1rem; }
    label { display: block; margin-bottom: 0.45rem; color: #334155; font-weight: 600; }
    input {
      width: 100%;
      padding: 12px 15px;
      border: 2px solid #e2e8f0;
      border-radius: 8px;
      font-size: 1rem;
    }
    input:focus { outline: none; border-color: #1b4f8a; box-shadow: 0 0 0 3px rgba(27, 79, 138, 0.14); }
    .btn {
      width: 100%;
      padding: 12px;
      border: none;
      border-radius: 8px;
      background: linear-gradient(135deg, #1b4f8a 0%, #d4a84a 100%);
      color: #ffffff;
      font-weight: 700;
      cursor: pointer;
    }
    .message { padding: 1rem; border-radius: 8px; margin-bottom: 1rem; }
    .message.error { background: #fed7d7; color: #742a2a; border-left: 4px solid #f56565; }
  </style>
</head>
<body>
  <div class="auth-wrapper">
    <div class="auth-box">
      <h1>Change Password</h1>
      <p>Your account uses a temporary password. Change it before continuing to ShieldURL.</p>
      <?php if ($message): ?>
        <div class="message <?php echo htmlspecialchars($messageType); ?>"><?php echo htmlspecialchars($message); ?></div>
      <?php endif; ?>
      <form method="POST">
        <div class="form-group">
          <label for="current_password">Current Temporary Password</label>
          <input type="password" id="current_password" name="current_password" required autocomplete="current-password">
        </div>
        <div class="form-group">
          <label for="new_password">New Password</label>
          <input type="password" id="new_password" name="new_password" required autocomplete="new-password">
        </div>
        <div class="form-group">
          <label for="confirm_password">Confirm New Password</label>
          <input type="password" id="confirm_password" name="confirm_password" required autocomplete="new-password">
        </div>
        <button class="btn" type="submit">Save Password</button>
      </form>
    </div>
  </div>
</body>
</html>
