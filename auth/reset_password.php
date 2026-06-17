<?php
require_once '../config/db.php';
require_once '../shared/audit.php';

if (isset($_SESSION['user_id'])) {
    header("Location: ../index.php");
    exit();
}

$db = new Database();
$conn = $db->getConnection();
$message = '';
$messageType = '';
$token = trim($_GET['token'] ?? ($_POST['token'] ?? ''));
$tokenHash = $token !== '' ? hash('sha256', $token) : '';
$user = null;

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

if ($tokenHash !== '') {
    $stmt = $conn->prepare("
        SELECT id, username, email, password, role, department
        FROM users
        WHERE password_reset_token_hash=? AND password_reset_expires_at > NOW() AND is_active=TRUE
        LIMIT 1
    ");
    $stmt->execute([$tokenHash]);
    $user = $stmt->fetch();
}

if (!$user) {
    $message = 'This password reset link is invalid or expired.';
    $messageType = 'error';
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $newPassword = $_POST['new_password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';

    if ($newPassword === '' || $confirmPassword === '') {
        $message = 'Please complete all password fields.';
        $messageType = 'error';
    } elseif ($newPassword !== $confirmPassword) {
        $message = 'Confirm password must match the new password.';
        $messageType = 'error';
    } elseif (password_verify($newPassword, $user['password'])) {
        $message = 'New password must be different from your current password.';
        $messageType = 'error';
    } elseif ($error = password_strength_error($newPassword)) {
        $message = $error;
        $messageType = 'error';
    } else {
        $hashed = password_hash($newPassword, PASSWORD_DEFAULT);
        $update = $conn->prepare("
            UPDATE users
            SET password=?, force_password_change=FALSE, account_status='active',
                password_reset_token_hash=NULL, password_reset_expires_at=NULL
            WHERE id=?
        ");
        $update->execute([$hashed, $user['id']]);
        audit_log($conn, 'password_reset_completed', "Password reset completed for '{$user['username']}'", 'success', [
            'user_id' => $user['id'],
            'username' => $user['username'],
            'role' => $user['role'],
            'division' => $user['department'] ?? null,
        ]);
        header("Location: login.php?reset=1");
        exit();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset Password - ShieldURL</title>
  <style>
    * { box-sizing: border-box; }
    body { margin: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
    .auth-wrapper {
      min-height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      background: radial-gradient(circle at top, #eef2ff 0%, #f8fafc 45%, #eaf2ff 100%);
      padding: 1rem;
    }
    .auth-box {
      width: 100%;
      max-width: 460px;
      background: #ffffff;
      padding: 2.4rem;
      border-radius: 16px;
      box-shadow: 0 18px 60px rgba(11, 31, 58, 0.22);
      border: 1px solid rgba(203, 213, 225, 0.75);
    }
    h1 { margin: 0 0 0.5rem; color: #0b1f3a; }
    p { margin: 0 0 1.4rem; color: #64748b; line-height: 1.5; }
    .form-group { margin-bottom: 1rem; }
    label { display: block; margin-bottom: 0.45rem; color: #334155; font-weight: 700; }
    input {
      width: 100%;
      padding: 12px 15px;
      border: 2px solid #e2e8f0;
      border-radius: 10px;
      font-size: 1rem;
    }
    input:focus { outline: none; border-color: #2563eb; box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.14); }
    .btn {
      width: 100%;
      padding: 12px;
      border: none;
      border-radius: 10px;
      background: linear-gradient(135deg, #1b4f8a 0%, #2563eb 100%);
      color: #ffffff;
      font-weight: 800;
      cursor: pointer;
    }
    .message { padding: 1rem; border-radius: 10px; margin-bottom: 1rem; }
    .message.error { background: #fee2e2; color: #991b1b; border-left: 4px solid #ef4444; }
    .back-link { display: inline-block; margin-top: 1rem; color: #1d4ed8; text-decoration: none; font-weight: 700; }
  </style>
</head>
<body>
  <div class="auth-wrapper">
    <div class="auth-box">
      <h1>Reset Password</h1>
      <p>Create a new password for your ShieldURL account.</p>
      <?php if ($message): ?>
        <div class="message <?php echo htmlspecialchars($messageType); ?>"><?php echo htmlspecialchars($message); ?></div>
      <?php endif; ?>
      <?php if ($user): ?>
        <form method="POST">
          <input type="hidden" name="token" value="<?php echo htmlspecialchars($token); ?>">
          <div class="form-group">
            <label for="new_password">New Password</label>
            <input type="password" id="new_password" name="new_password" required autocomplete="new-password">
          </div>
          <div class="form-group">
            <label for="confirm_password">Confirm New Password</label>
            <input type="password" id="confirm_password" name="confirm_password" required autocomplete="new-password">
          </div>
          <button class="btn" type="submit">Reset Password</button>
        </form>
      <?php endif; ?>
      <a class="back-link" href="login.php">Back to login</a>
    </div>
  </div>
</body>
</html>
