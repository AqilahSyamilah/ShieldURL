<?php
require_once '../config/db.php';
require_once '../shared/audit.php';
require_once '../shared/mailer.php';

if (isset($_SESSION['user_id'])) {
    header("Location: ../index.php");
    exit();
}

$message = '';
$messageType = '';

function reset_base_url()
{
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['SERVER_PORT'] ?? '') == 443);
    $scheme = $https ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $path = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/auth'), '/\\');
    return "{$scheme}://{$host}{$path}";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $identifier = trim($_POST['identifier'] ?? '');
    $message = 'If the account exists, a password reset link has been sent.';
    $messageType = 'success';

    if ($identifier !== '') {
        $db = new Database();
        $conn = $db->getConnection();

        $stmt = $conn->prepare("SELECT id, username, email, role, department FROM users WHERE (username=? OR email=?) AND is_active=TRUE LIMIT 1");
        $stmt->execute([$identifier, $identifier]);
        $user = $stmt->fetch();

        if ($user && !empty($user['email'])) {
            $token = bin2hex(random_bytes(32));
            $tokenHash = hash('sha256', $token);
            $expiresAt = date('Y-m-d H:i:s', time() + 3600);

            $update = $conn->prepare("UPDATE users SET password_reset_token_hash=?, password_reset_expires_at=? WHERE id=?");
            $update->execute([$tokenHash, $expiresAt, $user['id']]);

            $resetLink = reset_base_url() . '/reset_password.php?token=' . urlencode($token);
            $body = "Hello {$user['username']},\n\n"
                . "A password reset was requested for your ShieldURL account.\n\n"
                . "Reset your password using this link:\n{$resetLink}\n\n"
                . "This link expires in 1 hour. If you did not request this, ignore this email.\n\n"
                . "ShieldURL";

            shieldurl_send_mail($user['email'], 'ShieldURL Password Reset', $body);
            audit_log($conn, 'password_reset_requested', "Password reset requested for '{$user['username']}'", 'success', [
                'user_id' => $user['id'],
                'username' => $user['username'],
                'role' => $user['role'],
                'division' => $user['department'] ?? null,
            ]);
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Forgot Password - ShieldURL</title>
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
      margin-top: 1rem;
      padding: 12px;
      border: none;
      border-radius: 10px;
      background: linear-gradient(135deg, #1b4f8a 0%, #2563eb 100%);
      color: #ffffff;
      font-weight: 800;
      cursor: pointer;
    }
    .message { padding: 1rem; border-radius: 10px; margin-bottom: 1rem; }
    .message.success { background: #dcfce7; color: #166534; border-left: 4px solid #22c55e; }
    .message.error { background: #fee2e2; color: #991b1b; border-left: 4px solid #ef4444; }
    .back-link { display: inline-block; margin-top: 1rem; color: #1d4ed8; text-decoration: none; font-weight: 700; }
  </style>
</head>
<body>
  <div class="auth-wrapper">
    <div class="auth-box">
      <h1>Forgot Password</h1>
      <p>Enter your username or email. If the account exists, ShieldURL will send a reset link.</p>
      <?php if ($message): ?>
        <div class="message <?php echo htmlspecialchars($messageType); ?>"><?php echo htmlspecialchars($message); ?></div>
      <?php endif; ?>
      <form method="POST">
        <label for="identifier">Username or Email</label>
        <input type="text" id="identifier" name="identifier" required autocomplete="username">
        <button class="btn" type="submit">Send Reset Link</button>
      </form>
      <a class="back-link" href="login.php">Back to login</a>
    </div>
  </div>
</body>
</html>
