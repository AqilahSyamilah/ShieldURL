<?php
require_once '../config/db.php';
require_once '../shared/mailer.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

if (!empty($_SESSION['force_password_change'])) {
    header("Location: change_password.php?first_login=1");
    exit();
}

$db = new Database();
$conn = $db->getConnection();
$message = '';
$messageType = '';

function redirect_dashboard($role)
{
    if ($role === 'admin') {
        header("Location: ../admin/index.php?transition=1");
    } else {
        header("Location: ../index.php?transition=1");
    }
    exit();
}

function send_email_code($email, $name, $code)
{
    $subject = 'Your ShieldURL verification code';
    $body = "Hello {$name},\n\n"
        . "Your ShieldURL MFA verification code is: {$code}\n\n"
        . "This code expires in 10 minutes. If you did not try to sign in, contact your administrator.\n\n"
        . "ShieldURL";
    return shieldurl_send_mail($email, $subject, $body);
}

function create_email_code($user)
{
    $code = (string)random_int(100000, 999999);
    $_SESSION['mfa_email_code_hash'] = password_hash($code, PASSWORD_DEFAULT);
    $_SESSION['mfa_email_code_expires'] = time() + 600;
    $_SESSION['mfa_email_code_sent_to'] = $user['email'];
    $_SESSION['mfa_email_code_sent_at'] = time();
    return send_email_code($user['email'], $user['full_name'] ?: $user['username'], $code);
}

$stmt = $conn->prepare("SELECT id, full_name, username, email, role, force_password_change, mfa_required, mfa_configured FROM users WHERE id=? AND is_active=TRUE LIMIT 1");
$stmt->execute([$_SESSION['user_id']]);
$user = $stmt->fetch();

if (!$user) {
    session_destroy();
    header("Location: login.php?err=User not found");
    exit();
}

$_SESSION['mfa_required'] = (bool)$user['mfa_required'];
$_SESSION['mfa_configured'] = (bool)$user['mfa_configured'];

if (!empty($user['force_password_change'])) {
    $_SESSION['force_password_change'] = true;
    header("Location: change_password.php?first_login=1");
    exit();
}

if (empty($user['mfa_required']) || !empty($user['mfa_configured'])) {
    redirect_dashboard($_SESSION['role'] ?? $user['role']);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? 'verify';
    if ($action === 'resend') {
        $sent = create_email_code($user);
        $message = $sent
            ? 'A new verification code was sent to your email.'
            : 'A new code was generated. SMTP email is not configured, so check the PHP error log.';
        $messageType = $sent ? 'success' : 'error';
    } else {
        $code = preg_replace('/\D/', '', $_POST['code'] ?? '');
        $hash = $_SESSION['mfa_email_code_hash'] ?? '';
        $expires = (int)($_SESSION['mfa_email_code_expires'] ?? 0);
        $sentTo = $_SESSION['mfa_email_code_sent_to'] ?? '';

        if (strlen($code) !== 6) {
            $message = 'Enter the 6-digit code sent to your email.';
            $messageType = 'error';
        } elseif (!$hash || $sentTo !== $user['email'] || time() > $expires) {
            $message = 'Verification code expired. Send a new code and try again.';
            $messageType = 'error';
        } elseif (!password_verify($code, $hash)) {
            $message = 'Invalid verification code. Check your email and try again.';
            $messageType = 'error';
        } else {
            $update = $conn->prepare("UPDATE users SET mfa_configured=TRUE WHERE id=?");
            $update->execute([$_SESSION['user_id']]);
            $_SESSION['mfa_configured'] = true;
            unset($_SESSION['mfa_email_code_hash'], $_SESSION['mfa_email_code_expires'], $_SESSION['mfa_email_code_sent_to'], $_SESSION['mfa_email_code_sent_at']);
            redirect_dashboard($_SESSION['role'] ?? $user['role']);
        }
    }
} elseif (
    empty($_SESSION['mfa_email_code_hash'])
    || ($_SESSION['mfa_email_code_sent_to'] ?? '') !== $user['email']
    || time() > (int)($_SESSION['mfa_email_code_expires'] ?? 0)
) {
    $sent = create_email_code($user);
    if (!$sent) {
        $message = 'SMTP email is not configured, so the verification code was written to the PHP error log.';
        $messageType = 'error';
    }
}

$maskedEmail = preg_replace('/(^.).*(@.*$)/', '$1***$2', $user['email']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Email MFA - ShieldURL</title>
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
      max-width: 480px;
      background: #ffffff;
      padding: 2.5rem;
      border-radius: 15px;
      box-shadow: 0 15px 60px rgba(11, 31, 58, 0.22);
      border: 1px solid rgba(203, 213, 225, 0.75);
    }
    h1 { margin: 0 0 0.5rem; color: #0b1f3a; }
    p { color: #64748b; line-height: 1.5; }
    .form-group { margin: 1.2rem 0; }
    label { display: block; margin-bottom: 0.45rem; color: #334155; font-weight: 600; }
    input {
      width: 100%;
      padding: 12px 15px;
      border: 2px solid #e2e8f0;
      border-radius: 8px;
      font-size: 1.1rem;
      letter-spacing: 0.08em;
      text-align: center;
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
    .btn-secondary {
      margin-top: 0.75rem;
      background: #eff6ff;
      color: #1e3a8a;
      border: 1px solid #bfdbfe;
    }
    .message { padding: 1rem; border-radius: 8px; margin-bottom: 1rem; }
    .message.success { background: #c6f6d5; color: #22543d; border-left: 4px solid #48bb78; }
    .message.error { background: #fed7d7; color: #742a2a; border-left: 4px solid #f56565; }
  </style>
</head>
<body>
  <div class="auth-wrapper">
    <div class="auth-box">
      <h1>Email Verification</h1>
      <p>Enter the 6-digit code sent to <?php echo htmlspecialchars($maskedEmail); ?>. New users must complete this step before accessing the dashboard.</p>
      <?php if (isset($_GET['password_changed'])): ?>
        <div class="message success">Password changed successfully. Verify your email to continue.</div>
      <?php endif; ?>
      <?php if ($message): ?>
        <div class="message <?php echo htmlspecialchars($messageType); ?>"><?php echo htmlspecialchars($message); ?></div>
      <?php endif; ?>
      <form method="POST">
        <input type="hidden" name="action" value="verify">
        <div class="form-group">
          <label for="code">Verification Code</label>
          <input type="text" id="code" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autocomplete="one-time-code">
        </div>
        <button class="btn" type="submit">Verify and Continue</button>
      </form>
      <form method="POST">
        <input type="hidden" name="action" value="resend">
        <button class="btn btn-secondary" type="submit">Send New Code</button>
      </form>
    </div>
  </div>
</body>
</html>
