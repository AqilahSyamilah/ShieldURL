<?php
require_once '../config/db.php';

if (isset($_SESSION['user_id'])) {
  if (!empty($_SESSION['force_password_change'])) {
    header("Location: change_password.php?first_login=1");
    exit();
  }
  if (!empty($_SESSION['mfa_required']) && empty($_SESSION['mfa_configured'])) {
    header("Location: mfa_setup.php");
    exit();
  }
  if ($_SESSION['role'] === 'admin') {
    header("Location: ../admin/index.php");
  } else {
    header("Location: ../index.php");
  }
  exit();
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login - ShieldURL</title>
  <style>
    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      overflow-x: hidden;
    }

    .login-wrapper {
      min-height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      background:
        radial-gradient(circle at 18% 18%, rgba(96, 165, 250, 0.26), transparent 30%),
        radial-gradient(circle at 82% 12%, rgba(168, 85, 247, 0.22), transparent 28%),
        linear-gradient(135deg, #081527 0%, #10294a 38%, #4c1d95 72%, #1d4ed8 100%);
      background-size: 160% 160%;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      padding: 2rem 1rem;
      position: relative;
      isolation: isolate;
      animation: gradientDrift 18s ease-in-out infinite;
      overflow: hidden;
    }

    .login-wrapper::before,
    .login-wrapper::after {
      content: "";
      position: absolute;
      width: 360px;
      height: 360px;
      border-radius: 999px;
      filter: blur(28px);
      opacity: 0.42;
      pointer-events: none;
      z-index: -1;
      animation: floatGlow 12s ease-in-out infinite;
    }

    .login-wrapper::before {
      left: max(-120px, -8vw);
      top: 12vh;
      background: rgba(59, 130, 246, 0.5);
    }

    .login-wrapper::after {
      right: max(-140px, -10vw);
      bottom: 8vh;
      background: rgba(147, 51, 234, 0.45);
      animation-delay: -4s;
    }

    .login-box {
      background: rgba(255, 255, 255, 0.88);
      backdrop-filter: blur(18px);
      -webkit-backdrop-filter: blur(18px);
      padding: 3rem;
      border-radius: 22px;
      border: 1px solid rgba(219, 234, 254, 0.72);
      box-shadow: 0 24px 70px rgba(8, 21, 39, 0.38);
      width: 100%;
      max-width: 520px;
      position: relative;
      animation: cardIntro 0.75s cubic-bezier(0.22, 1, 0.36, 1) both;
    }

    .login-box::before {
      content: "";
      position: absolute;
      inset: 1px;
      border-radius: 21px;
      pointer-events: none;
      background: linear-gradient(135deg, rgba(255, 255, 255, 0.58), transparent 38%);
    }

    .login-box > * {
      position: relative;
    }

    @keyframes cardIntro {
      from {
        opacity: 0;
        transform: translateY(18px);
      }

      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    @keyframes gradientDrift {
      0%, 100% {
        background-position: 0% 50%;
      }

      50% {
        background-position: 100% 50%;
      }
    }

    @keyframes floatGlow {
      0%, 100% {
        transform: translate3d(0, 0, 0) scale(1);
      }

      50% {
        transform: translate3d(22px, -18px, 0) scale(1.06);
      }
    }

    .login-header {
      text-align: center;
      margin-bottom: 1.55rem;
    }

    .logo-mark {
      width: 190px;
      height: 190px;
      object-fit: contain;
      display: block;
      margin: -0.65rem auto 0.25rem;
      border-radius: 20px;
      filter: drop-shadow(0 0 18px rgba(96, 165, 250, 0.48));
      animation: logoGlow 4s ease-in-out infinite;
    }

    @keyframes logoGlow {
      0%, 100% {
        filter: drop-shadow(0 0 14px rgba(96, 165, 250, 0.42));
      }

      50% {
        filter: drop-shadow(0 0 24px rgba(124, 58, 237, 0.5));
      }
    }

    .login-header h1 {
      color: #0f172a;
      font-size: 2rem;
      margin: 0 0 0.35rem;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    .login-header p {
      color: #475569;
      font-size: 0.9rem;
      margin: 0;
    }

    .form-group {
      margin-bottom: 1.5rem;
      position: relative;
    }

    .form-group label {
      display: block;
      margin-bottom: 0.5rem;
      color: #1e293b;
      font-weight: 650;
      font-size: 0.95rem;
    }

    .form-group input {
      width: 100%;
      padding: 13px 15px;
      border: 1px solid rgba(148, 163, 184, 0.55);
      border-radius: 12px;
      font-size: 1rem;
      transition: border-color 0.25s ease, box-shadow 0.25s ease, background 0.25s ease, transform 0.25s ease;
      background: rgba(248, 250, 252, 0.9);
      color: #0f172a;
    }

    .form-group input:focus {
      outline: none;
      border-color: #6366f1;
      background: white;
      box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.14), 0 12px 24px rgba(37, 99, 235, 0.12);
      transform: translateY(-1px);
    }

    .form-group input::placeholder {
      color: #999;
    }

    .btn-login {
      width: 100%;
      padding: 12px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      border-radius: 12px;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.25s ease, box-shadow 0.25s ease, filter 0.25s ease;
      position: relative;
      overflow: hidden;
      box-shadow: 0 12px 24px rgba(102, 126, 234, 0.28);
    }

    .btn-login:hover {
      transform: translateY(-2px);
      filter: brightness(1.04);
      box-shadow: 0 16px 34px rgba(102, 126, 234, 0.42);
    }

    .btn-login:active {
      transform: translateY(0);
    }

    .btn-login:disabled {
      opacity: 0.7;
      cursor: not-allowed;
    }

    .loader {
      display: none;
      width: 16px;
      height: 16px;
      border: 3px solid rgba(255, 255, 255, 0.3);
      border-top: 3px solid white;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      position: absolute;
      left: 15px;
      top: 50%;
      transform: translateY(-50%);
    }

    @keyframes spin {
      0% {
        transform: translateY(-50%) rotate(0deg);
      }

      100% {
        transform: translateY(-50%) rotate(360deg);
      }
    }

    .btn-login.loading .loader {
      display: block;
    }

    .btn-login.loading .btn-text {
      margin-left: 20px;
    }

    .error-box {
      background: rgba(254, 226, 226, 0.9);
      border-left: 4px solid #ef4444;
      color: #991b1b;
      padding: 1rem;
      border-radius: 12px;
      margin-bottom: 1.5rem;
      animation: shake 0.5s ease-in-out;
    }

    @keyframes shake {

      0%,
      100% {
        transform: translateX(0);
      }

      25% {
        transform: translateX(-10px);
      }

      75% {
        transform: translateX(10px);
      }
    }

    .error-box strong {
      color: #f44;
    }

    .login-footer {
      text-align: center;
      margin-top: 2rem;
      padding-top: 1.5rem;
      border-top: 1px solid #eee;
      font-size: 0.85rem;
      color: #666;
    }

    .login-footer .demo-creds {
      background: #f0f4ff;
      padding: 0.8rem;
      border-radius: 5px;
      margin-top: 1rem;
      color: #333;
    }

    .login-footer .demo-creds strong {
      color: #667eea;
    }

    @media (max-width: 480px) {
      .login-box {
        padding: 2rem;
        margin: 1rem;
        border-radius: 18px;
        max-width: 100%;
      }

      .login-header h1 {
        font-size: 1.5rem;
      }

      .logo-mark {
        width: 145px;
        height: 145px;
        margin-top: -0.35rem;
        margin-bottom: 0.15rem;
      }
    }

    @media (prefers-reduced-motion: reduce) {
      *,
      *::before,
      *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        scroll-behavior: auto !important;
      }
    }
  </style>
</head>

<body>
  <div class="login-wrapper">
    <div class="login-box">
      <div class="login-header">
        <img class="logo-mark" src="../img/logo.png" alt="ShieldURL logo">
        <h1>ShieldURL</h1>
        <p>Secure Login Portal</p>
      </div>

      <?php if (isset($_GET['err'])): ?>
        <div class="error-box">
          <strong>Error:</strong> <?php echo htmlspecialchars($_GET['err']); ?>
        </div>
      <?php endif; ?>

      <form method="POST" action="login_process.php" id="loginForm" onsubmit="handleLogin(event)">
        <div class="form-group">
          <label for="username">Username</label>
          <input type="text" id="username" name="username" placeholder="Enter your username" required
            autocomplete="username">
        </div>

        <div class="form-group">
          <label for="password">Password</label>
          <input type="password" id="password" name="password" placeholder="Enter your password" required
            autocomplete="current-password">
        </div>

        <button type="submit" class="btn-login" id="loginBtn">
          <div class="loader"></div>
          <span class="btn-text">Sign In</span>
        </button>
      </form>

<!--
<div class="login-footer">
  <p>Demo Credentials</p>
  <div class="demo-creds">
    <p><strong>Admin</strong><br>Username: <code>admin</code><br>Password: <code>admin123</code></p>
    <p><strong>User</strong><br>Username: <code>aqilah</code><br>Password: <code>123456</code></p>
  </div>
</div>
-->
    </div>
  </div>

  <script>
    function handleLogin(event) {
      event.preventDefault();
      const loginBtn = document.getElementById('loginBtn');
      const username = document.getElementById('username').value.trim();
      const password = document.getElementById('password').value;

      if (!username || !password) {
        alert('Please enter both username and password');
        return;
      }

      loginBtn.disabled = true;
      loginBtn.classList.add('loading');

      // Simulate form submission with visual feedback
      setTimeout(() => {
        document.getElementById('loginForm').submit();
      }, 300);
    }

    // Add keyboard shortcut for login (Enter key)
    document.getElementById('loginForm').addEventListener('keypress', function (e) {
      if (e.key === 'Enter') {
        document.getElementById('loginBtn').click();
      }
    });

    // Focus username input on load
    window.addEventListener('load', () => {
      document.getElementById('username').focus();
    });
  </script>
</body>

</html>
