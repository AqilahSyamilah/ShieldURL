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
    }

    .login-wrapper {
      min-height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }

    .login-box {
      background: white;
      padding: 3rem;
      border-radius: 15px;
      box-shadow: 0 15px 60px rgba(0, 0, 0, 0.3);
      width: 100%;
      max-width: 420px;
      animation: slideUp 0.6s ease-out;
    }

    @keyframes slideUp {
      from {
        opacity: 0;
        transform: translateY(30px);
      }

      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    .login-header {
      text-align: center;
      margin-bottom: 2rem;
    }

    .login-header h1 {
      color: #333;
      font-size: 2rem;
      margin-bottom: 0.5rem;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    .login-header p {
      color: #666;
      font-size: 0.9rem;
    }

    .form-group {
      margin-bottom: 1.5rem;
      position: relative;
    }

    .form-group label {
      display: block;
      margin-bottom: 0.5rem;
      color: #333;
      font-weight: 500;
      font-size: 0.95rem;
    }

    .form-group input {
      width: 100%;
      padding: 12px 15px;
      border: 2px solid #e0e0e0;
      border-radius: 8px;
      font-size: 1rem;
      transition: all 0.3s ease;
      background: #f9f9f9;
    }

    .form-group input:focus {
      outline: none;
      border-color: #667eea;
      background: white;
      box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
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
      border-radius: 8px;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s ease;
      position: relative;
      overflow: hidden;
    }

    .btn-login:hover {
      transform: translateY(-2px);
      box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4);
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
      background: #fee;
      border-left: 4px solid #f44;
      color: #c33;
      padding: 1rem;
      border-radius: 5px;
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
      }

      .login-header h1 {
        font-size: 1.5rem;
      }
    }
  </style>
</head>

<body>
  <div class="login-wrapper">
    <div class="login-box">
      <div class="login-header">
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
          <label for="username">Email or Username</label>
          <input type="text" id="username" name="username" placeholder="Enter your email or username" required
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
