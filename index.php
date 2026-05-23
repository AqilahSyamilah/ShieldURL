<?php
session_start();

require_once 'config/db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: auth/login.php");
    exit();
}

$db = new Database();
$conn = $db->getConnection();

$authStmt = $conn->prepare("
    SELECT force_password_change, mfa_required, mfa_configured
    FROM users
    WHERE id = ? AND is_active = TRUE
    LIMIT 1
");
$authStmt->execute([$_SESSION['user_id']]);
$authUser = $authStmt->fetch();

if (!$authUser) {
    session_destroy();
    header("Location: auth/login.php?err=User not found");
    exit();
}

$_SESSION['force_password_change'] = (bool)$authUser['force_password_change'];
$_SESSION['mfa_required'] = (bool)$authUser['mfa_required'];
$_SESSION['mfa_configured'] = (bool)$authUser['mfa_configured'];

$currentPage = basename($_SERVER['PHP_SELF']);
$show_transition = ($_GET['transition'] ?? '') === '1';

/* FORCE PASSWORD CHANGE */
if ($_SESSION['force_password_change'] && $currentPage !== 'change_password.php') {
    header("Location: auth/change_password.php?first_login=1");
    exit();
}

/* FORCE MFA SETUP */
if (
    $_SESSION['mfa_required'] &&
    !$_SESSION['mfa_configured'] &&
    !in_array($currentPage, ['mfa_setup.php', 'verify_2fa.php'])
) {
    header("Location: auth/mfa_setup.php");
    exit();
}

/* FORCE MFA VERIFICATION EVERY LOGIN SESSION */
if (
    $_SESSION['mfa_required'] &&
    $_SESSION['mfa_configured'] &&
    empty($_SESSION['mfa_verified']) &&
    $currentPage !== 'verify_2fa.php'
) {
    header("Location: auth/verify_2fa.php");
    exit();
}

$total_checks = 0;
$safe_count = 0;
$phishing_count = 0;

try {
    $statsStmt = $conn->prepare("
        SELECT
            COUNT(*) AS total_checks,
            SUM(CASE WHEN status = 'safe' THEN 1 ELSE 0 END) AS safe_count,
            SUM(CASE WHEN status = 'phishing' THEN 1 ELSE 0 END) AS phishing_count
        FROM url_logs
        WHERE user_id = ?
    ");
    $statsStmt->execute([$_SESSION['user_id']]);
    $stats = $statsStmt->fetch();

    $total_checks = (int)($stats['total_checks'] ?? 0);
    $safe_count = (int)($stats['safe_count'] ?? 0);
    $phishing_count = (int)($stats['phishing_count'] ?? 0);
} catch (Exception $e) {
    $total_checks = 0;
    $safe_count = 0;
    $phishing_count = 0;
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShieldURL - URL Checker</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        html {
            scroll-behavior: smooth;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: radial-gradient(circle at top, #10294a 0%, #0b1f3a 55%, #081527 100%);
            color: #0f172a;
        }

        body::before {
            content: "";
            position: fixed;
            inset: 0;
            background:
                radial-gradient(circle at 15% 10%, rgba(27, 79, 138, 0.12), transparent 45%),
                radial-gradient(circle at 85% 15%, rgba(212, 168, 74, 0.12), transparent 40%),
                radial-gradient(circle at 35% 80%, rgba(11, 31, 58, 0.08), transparent 50%);
            pointer-events: none;
            z-index: 0;
        }

        .transition-overlay {
            position: fixed;
            inset: 0;
            background: linear-gradient(135deg, rgba(11, 31, 58, 0.96), rgba(27, 79, 138, 0.96));
            display: grid;
            place-items: center;
            z-index: 9999;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.4s ease;
        }

        .has-transition .transition-overlay {
            opacity: 1;
            pointer-events: auto;
        }

        .transition-shield {
            position: relative;
            width: 140px;
            height: 170px;
            background: linear-gradient(160deg, #ffffff, #e2e8f0);
            clip-path: polygon(50% 0%, 90% 12%, 100% 46%, 50% 100%, 0 46%, 10% 12%);
            box-shadow: 0 20px 40px rgba(15, 23, 42, 0.25);
            animation: transitionFloat 1.6s ease-in-out infinite;
            display: grid;
            place-items: center;
            overflow: hidden;
        }

        .transition-scan {
            position: absolute;
            left: 0;
            right: 0;
            height: 6px;
            background: linear-gradient(90deg, transparent, rgba(212, 168, 74, 0.9), transparent);
            top: -10px;
            animation: transitionScan 1.4s ease-in-out infinite;
        }

        .transition-ring {
            position: absolute;
            width: 210px;
            height: 210px;
            border-radius: 50%;
            border: 2px solid rgba(255, 255, 255, 0.5);
            box-shadow: 0 0 30px rgba(255, 255, 255, 0.35);
            animation: transitionPulse 2.2s ease-out infinite;
        }

        .transition-label {
            font-weight: 700;
            letter-spacing: 0.2em;
            color: #d4a84a;
            text-transform: uppercase;
        }

        @keyframes transitionFloat {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-12px); }
        }

        @keyframes transitionScan {
            0% { transform: translateY(-18px); opacity: 0; }
            25% { opacity: 1; }
            60% { transform: translateY(120px); opacity: 0.85; }
            100% { transform: translateY(180px); opacity: 0; }
        }

        @keyframes transitionPulse {
            0% { transform: scale(0.9); opacity: 0.45; }
            70% { transform: scale(1.1); opacity: 0; }
            100% { transform: scale(1.1); opacity: 0; }
        }

        @keyframes headerGlow {
            0%, 100% { opacity: 0.65; }
            50% { opacity: 1; }
        }

        @keyframes headerSweep {
            0% { transform: translateX(-120%); }
            50% { transform: translateX(120%); }
            100% { transform: translateX(120%); }
        }

        .user-header {
            position: relative;
            background: linear-gradient(135deg, #0b1f3a 0%, #123b6d 55%, #1b4f8a 100%);
            color: white;
            padding: 1.5rem 2rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
            overflow: hidden;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            z-index: 10;
            transform: translateY(-120%);
            opacity: 0;
            transition: transform 0.35s ease, opacity 0.35s ease, box-shadow 0.35s ease, padding 0.35s ease;
        }

        .user-header::before {
            content: "";
            position: absolute;
            inset: 0;
            background:
                radial-gradient(circle at 20% 30%, rgba(212, 168, 74, 0.25), transparent 45%),
                radial-gradient(circle at 80% 20%, rgba(255, 255, 255, 0.08), transparent 55%);
            opacity: 0.8;
            animation: headerGlow 8s ease-in-out infinite;
        }

        .user-header::after {
            content: "";
            position: absolute;
            top: 0;
            bottom: 0;
            width: 35%;
            background: linear-gradient(120deg, transparent, rgba(255, 255, 255, 0.18), transparent);
            transform: translateX(-120%);
            animation: headerSweep 6s ease-in-out infinite;
        }

        .user-header.is-visible {
            transform: translateY(0);
            opacity: 1;
        }

        .user-header.scrolled {
            padding: 0.8rem 2rem;
            box-shadow: 0 12px 28px rgba(11, 31, 58, 0.35);
        }

        .user-header.scrolled .brand img {
            height: 120px;
        }

        .brand img {
            transition: height 0.3s ease;
        }
        .brand {
            display: flex;
            align-items: center;
            gap: 0.9rem;
            position: relative;
            z-index: 1;
        }

        .brand img {
            width: auto;
            height: 160px;
            object-fit: contain;
            filter: drop-shadow(0 6px 12px rgba(0, 0, 0, 0.35));
            display: block;
        }

        .brand-title {
            font-size: 2rem;
            font-weight: 700;
            letter-spacing: 0.04em;
        }

        .user-info {
            display: flex;
            gap: 1rem;
            align-items: center;
            position: relative;
            z-index: 1;
        }

        .user-profile-chip {
            display: inline-flex;
            align-items: center;
            gap: 0.6rem;
            background: rgba(255, 255, 255, 0.12);
            border: 1px solid rgba(255, 255, 255, 0.28);
            border-radius: 999px;
            padding: 0.35rem 0.7rem 0.35rem 0.35rem;
        }

        .header-avatar {
            width: 34px;
            height: 34px;
            border-radius: 999px;
            object-fit: cover;
            border: 1px solid rgba(255, 255, 255, 0.6);
            background: rgba(255, 255, 255, 0.85);
        }

        .welcome-text {
            font-size: 0.95rem;
            color: #e2e8f0;
            white-space: nowrap;
        }

        .logout-btn {
            background: rgba(255, 255, 255, 0.2);
            color: white;
            padding: 0.7rem 1.5rem;
            border-radius: 5px;
            text-decoration: none;
            transition: all 0.3s;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }

        .logout-btn:hover {
            background: rgba(255, 255, 255, 0.3);
            transform: translateY(-2px);
        }

        .container {
            max-width: 1400px;
            margin: 2rem auto;
            padding: 0 1rem;
            position: relative;
            z-index: 1;
        }

        .header-spacer {
            height: 0;
            transition: height 0.35s ease;
        }

        .intro-hero {
            min-height: calc(100vh - 140px);
            display: grid;
            place-items: center;
            padding: 2rem 0 3rem;
        }

        .intro-card {
            text-align: center;
            padding: 3rem 2rem;
            background: linear-gradient(160deg, rgba(255, 255, 255, 0.88), rgba(255, 255, 255, 0.7));
            border-radius: 24px;
            box-shadow: 0 20px 50px rgba(11, 31, 58, 0.18);
            border: 1px solid rgba(27, 79, 138, 0.12);
            max-width: 640px;
        }

        .intro-logo {
            width: 400px;
            height: 350px;
            object-fit: contain;
            filter: drop-shadow(0 14px 28px rgba(11, 31, 58, 0.38));
            margin: -2.8rem auto -4.2rem;
        }

        .intro-title {
            font-size: clamp(2.4rem, 6vw, 3.6rem);
            letter-spacing: 0.08em;
            margin-bottom: 0.6rem;
            text-transform: uppercase;
            color: #0b1f3a;
        }

        .intro-subtitle {
            font-size: 1.05rem;
            color: #4a5568;
            margin-bottom: 2rem;
            line-height: 1.6;
        }

        .intro-cta {
            display: inline-flex;
            align-items: center;
            gap: 0.6rem;
            padding: 0.9rem 1.8rem;
            border-radius: 999px;
            background: linear-gradient(135deg, #1b4f8a 0%, #d4a84a 100%);
            color: white;
            text-decoration: none;
            font-weight: 600;
            letter-spacing: 0.04em;
            box-shadow: 0 10px 20px rgba(212, 168, 74, 0.35);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .intro-cta:hover {
            transform: translateY(-2px);
            box-shadow: 0 14px 28px rgba(212, 168, 74, 0.45);
        }

        .intro-hint {
            margin-top: 1.2rem;
            font-size: 0.9rem;
            color: #718096;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: white;
            padding: 1.5rem;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            text-align: center;
        }

        .stat-card h3 {
            color: #666;
            font-size: 0.85rem;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .stat-card .number {
            font-size: 2.5rem;
            font-weight: 700;
            color: #1b4f8a;
        }

        .card {
            background: #f8fafc;
            padding: 2rem;
            border-radius: 16px;
            box-shadow: 0 12px 30px rgba(8, 21, 39, 0.28);
            margin-bottom: 2rem;
            border: 1px solid rgba(203, 213, 225, 0.5);
        }

        .card h2 {
            margin-bottom: 1.5rem;
            color: #333;
            font-size: 1.5rem;
        }

        .check-form {
            display: grid;
            gap: 1rem;
        }

        .form-group {
            display: grid;
            gap: 0.5rem;
        }

        .form-group label {
            font-weight: 600;
            color: #333;
        }

        .form-group input,
        .form-group textarea {
            padding: 0.8rem;
            border: 1px solid #cbd5e1;
            border-radius: 12px;
            font-size: 1rem;
            font-family: inherit;
            transition: all 0.3s;
            background: #ffffff;
        }

        .form-group input:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: #2563eb;
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.16);
        }

        .form-row {
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 1rem;
        }

        .btn-check {
            background: linear-gradient(135deg, #1d4ed8 0%, #1b4f8a 100%);
            color: white;
            padding: 0.8rem 2rem;
            border: none;
            border-radius: 12px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.22s ease, box-shadow 0.22s ease, background 0.22s ease, opacity 0.22s ease;
            height: fit-content;
        }

        .btn-check:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 22px rgba(29, 78, 216, 0.35);
        }

        .btn-check:active {
            transform: translateY(0);
        }

        .shield-status {
            display: flex;
            align-items: center;
            gap: 1.5rem;
            margin-bottom: 1.5rem;
            padding: 1rem;
            border-radius: 12px;
            background: linear-gradient(120deg, rgba(102, 126, 234, 0.12), rgba(118, 75, 162, 0.08));
            border: 1px solid rgba(102, 126, 234, 0.2);
        }

        .shield-visual {
            position: relative;
            width: 120px;
            height: 140px;
            background: linear-gradient(150deg, var(--shield-main), var(--shield-deep));
            clip-path: polygon(50% 0%, 90% 12%, 100% 46%, 50% 100%, 0 46%, 10% 12%);
            box-shadow: 0 18px 30px rgba(15, 23, 42, 0.2), 0 0 28px var(--shield-glow);
            animation: float 5s ease-in-out infinite;
            display: grid;
            place-items: center;
            overflow: hidden;
        }

        .shield-burst {
            position: absolute;
            inset: -20px;
            border-radius: 999px;
            border: 2px solid rgba(255, 255, 255, 0.5);
            opacity: 0;
            transform: scale(0.6);
            pointer-events: none;
        }

        .shield-burst::after {
            content: "";
            position: absolute;
            inset: 8px;
            border-radius: 999px;
            border: 2px dashed rgba(255, 255, 255, 0.45);
        }

        .shield-visual::before {
            content: "";
            position: absolute;
            inset: 12px;
            border: 1px solid rgba(255, 255, 255, 0.6);
            clip-path: inherit;
            background: linear-gradient(160deg, rgba(255, 255, 255, 0.3), rgba(255, 255, 255, 0.05));
        }

        .shield-ring {
            position: absolute;
            width: 160px;
            height: 160px;
            border-radius: 50%;
            border: 2px solid var(--shield-ring);
            box-shadow: 0 0 20px var(--shield-ring);
            animation: pulse 3s ease-out infinite;
        }

        .shield-scan {
            position: absolute;
            left: 0;
            right: 0;
            height: 6px;
            background: linear-gradient(90deg, transparent, var(--shield-scan), transparent);
            top: -10px;
            animation: scan 2.4s ease-in-out infinite;
        }

        .shield-label {
            position: relative;
            z-index: 1;
            font-weight: 700;
            font-size: 0.85rem;
            letter-spacing: 0.2em;
            color: rgba(255, 255, 255, 0.92);
            text-transform: uppercase;
        }

        .shield-copy h3 {
            margin: 0 0 0.3rem;
            font-size: 1.1rem;
            color: #2d3748;
        }

        .shield-copy p {
            margin: 0;
            color: #4a5568;
            font-size: 0.95rem;
        }

        .result-message {
            padding: 1rem;
            border-radius: 5px;
            margin-top: 1rem;
            display: none;
        }

        .result-message.success {
            background: #c6f6d5;
            color: #22543d;
            border-left: 4px solid #48bb78;
            display: block;
        }

        .result-message.error {
            background: #fed7d7;
            color: #742a2a;
            border-left: 4px solid #f56565;
            display: block;
        }

        .result-message.loading {
            background: #bee3f8;
            color: #2c5282;
            border-left: 4px solid #3182ce;
            display: block;
        }

        .loading-spinner {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid rgba(255, 255, 255, 0.75);
            border-top-color: rgba(255, 255, 255, 1);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            vertical-align: middle;
            margin-right: 0.6rem;
        }

        @keyframes spin {
            100% { transform: rotate(360deg); }
        }

        .analysis-result {
            background: #f8fafc;
            padding: 1.5rem;
            border-radius: 16px;
            box-shadow: 0 12px 30px rgba(8, 21, 39, 0.28);
            margin-top: 2rem;
            display: none;
            border: 1px solid rgba(203, 213, 225, 0.6);
        }

        .analysis-result.show {
            display: block;
            animation: slideDown 0.3s ease-in;
        }

        .assistant-panel {
            border: 1px solid #dbe4ef;
            border-radius: 14px;
            background: #ffffff;
            overflow: hidden;
            box-shadow: 0 8px 18px rgba(15, 23, 42, 0.09);
        }

        .assistant-header {
            padding: 1rem;
            border-bottom: 1px solid #e2e8f0;
            background: #eff6ff;
        }

        .assistant-header h3 {
            margin: 0 0 0.25rem;
            color: #0b1f3a;
            font-size: 1.05rem;
        }

        .assistant-header p {
            margin: 0;
            color: #64748b;
            font-size: 0.92rem;
        }

        .assistant-starters {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            padding: 1rem;
            border-bottom: 1px solid #e2e8f0;
        }

        .assistant-starter {
            border: 1px solid #bfdbfe;
            background: #ffffff;
            color: #1e3a5f;
            border-radius: 999px;
            padding: 0.5rem 0.7rem;
            cursor: pointer;
            font: inherit;
            font-size: 0.9rem;
            transition: transform 0.2s ease, background 0.2s ease;
        }

        .assistant-starter:hover {
            transform: translateY(-1px);
            background: #f0f9ff;
        }

        .assistant-question-panel {
            padding: 1rem 1rem 0.6rem;
            background: #f8fafc;
            border-bottom: 1px solid #e2e8f0;
        }

        .assistant-question-title {
            color: #334155;
            font-size: 0.86rem;
            font-weight: 700;
            margin-bottom: 0.65rem;
        }

        .assistant-question-list {
            display: flex;
            gap: 0.55rem;
            flex-wrap: wrap;
        }

        .assistant-question-btn,
        .assistant-category-btn {
            border: 1px solid #bfdbfe;
            background: #ffffff;
            color: #1e3a5f;
            border-radius: 999px;
            padding: 0.56rem 0.78rem;
            cursor: pointer;
            font: inherit;
            font-size: 0.88rem;
            line-height: 1.2;
            transition: transform 0.2s ease, background 0.2s ease, border-color 0.2s ease, color 0.2s ease;
        }

        .assistant-question-btn:hover,
        .assistant-category-btn:hover {
            transform: translateY(-1px);
            background: #eff6ff;
            border-color: #93c5fd;
        }

        .assistant-category-bar {
            display: flex;
            gap: 0.6rem;
            flex-wrap: wrap;
            padding: 0.95rem 1rem;
            border-top: 1px solid #e2e8f0;
            background: #ffffff;
        }

        .assistant-category-btn {
            background: #dbeafe;
            color: #1e3a8a;
            font-weight: 700;
        }

        .assistant-category-btn.active {
            background: #1d4ed8;
            border-color: #1d4ed8;
            color: #ffffff;
        }

        .assistant-question-btn:disabled,
        .assistant-category-btn:disabled,
        .assistant-starter:disabled,
        .assistant-send:disabled,
        #assistantInput:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        .assistant-messages {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            min-height: 140px;
            max-height: 320px;
            overflow-y: auto;
            padding: 1rem;
            background: #f8fafc;
            position: relative;
        }

        .assistant-message {
            max-width: min(78%, 680px);
            border-radius: 14px;
            padding: 0.75rem 0.9rem;
            line-height: 1.5;
            white-space: pre-wrap;
            word-break: break-word;
            overflow-wrap: break-word;
            text-decoration: none;
            position: relative;
            z-index: 1;
        }

        .assistant-message,
        .assistant-message * {
            text-decoration: none;
        }

        .assistant-message::before,
        .assistant-message::after {
            content: none;
            display: none;
        }

        .assistant-message.message-enter {
            animation: messageSlideFade 0.35s ease both;
        }

        .assistant-message.user {
            align-self: flex-end;
            background: #1d4ed8;
            color: #ffffff;
        }

        .assistant-message.assistant {
            align-self: flex-start;
            background: #ffffff;
            color: #1f2937;
            border: 1px solid #e2e8f0;
            text-decoration: none;
            line-height: 1.5;
            overflow-wrap: break-word;
        }

        .assistant-answer-section + .assistant-answer-section {
            margin-top: 0.72rem;
        }

        .assistant-answer-label {
            display: block;
            color: #0f172a;
            font-weight: 800;
            margin-bottom: 0.18rem;
        }

        .assistant-answer-text {
            color: #334155;
        }

        .assistant-message.notice {
            align-self: center;
            max-width: 100%;
            background: transparent;
            color: #64748b;
            border: 1px dashed #cbd5e1;
            text-align: center;
        }

        .assistant-form {
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 0.75rem;
            padding: 1rem;
            border-top: 1px solid #e2e8f0;
            background: #ffffff;
        }

        #assistantInput {
            min-width: 0;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            padding: 0.75rem;
            font: inherit;
        }

        .assistant-send {
            border: none;
            border-radius: 12px;
            background: #1d4ed8;
            color: #ffffff;
            padding: 0.75rem 1rem;
            font-weight: 700;
            cursor: pointer;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .assistant-send:hover {
            transform: translateY(-1px);
            box-shadow: 0 8px 16px rgba(29, 78, 216, 0.35);
        }

        .assistant-note {
            padding: 0 1rem 1rem;
            color: #64748b;
            font-size: 0.86rem;
            background: #ffffff;
        }

        @keyframes slideDown {
            from {
                opacity: 0;
                transform: translateY(-20px);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes float {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-8px); }
        }

        @keyframes pulse {
            0% { transform: scale(0.9); opacity: 0.45; }
            70% { transform: scale(1.1); opacity: 0; }
            100% { transform: scale(1.1); opacity: 0; }
        }

        @keyframes scan {
            0% { transform: translateY(-18px); opacity: 0; }
            20% { opacity: 1; }
            60% { transform: translateY(120px); opacity: 0.85; }
            100% { transform: translateY(180px); opacity: 0; }
        }

        @keyframes sway {
            0%, 100% { transform: translateY(0) rotate(0deg); }
            50% { transform: translateY(-4px) rotate(1.5deg); }
        }

        @keyframes shake {
            0% { transform: translate(0, 0) rotate(0deg); }
            25% { transform: translate(-2px, 1px) rotate(-1deg); }
            50% { transform: translate(2px, -1px) rotate(1deg); }
            75% { transform: translate(-1px, -2px) rotate(-0.5deg); }
            100% { transform: translate(0, 0) rotate(0deg); }
        }

        @keyframes burst {
            0% { opacity: 0; transform: scale(0.55); }
            30% { opacity: 0.9; transform: scale(0.9); }
            100% { opacity: 0; transform: scale(1.4); }
        }

        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(14px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes messageSlideFade {
            from {
                opacity: 0;
                transform: translateY(8px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        body {
            --shield-main: #1b4f8a;
            --shield-deep: #0b1f3a;
            --shield-glow: rgba(212, 168, 74, 0.45);
            --shield-ring: rgba(212, 168, 74, 0.35);
            --shield-scan: rgba(255, 255, 255, 0.9);
        }

        body.status-scanning .shield-visual {
            animation-duration: 2.8s;
        }

        body.status-scanning .shield-scan {
            animation-duration: 1.6s;
        }

        body.status-safe {
            --shield-main: #48bb78;
            --shield-deep: #2f855a;
            --shield-glow: rgba(72, 187, 120, 0.55);
            --shield-ring: rgba(72, 187, 120, 0.35);
            --shield-scan: rgba(240, 253, 250, 0.95);
        }

        body.status-safe .shield-visual {
            animation-duration: 6s;
        }

        body.status-warn {
            --shield-main: #f6ad55;
            --shield-deep: #c05621;
            --shield-glow: rgba(246, 173, 85, 0.6);
            --shield-ring: rgba(246, 173, 85, 0.4);
            --shield-scan: rgba(255, 251, 235, 0.95);
        }

        body.status-warn .shield-visual {
            animation: float 4s ease-in-out infinite, sway 1.8s ease-in-out infinite;
        }

        body.status-warn .shield-scan {
            animation-duration: 1.9s;
        }

        body.status-danger {
            --shield-main: #f56565;
            --shield-deep: #c53030;
            --shield-glow: rgba(245, 101, 101, 0.6);
            --shield-ring: rgba(245, 101, 101, 0.45);
            --shield-scan: rgba(254, 226, 226, 0.95);
        }

        body.status-danger .shield-visual {
            animation: shake 0.9s linear infinite;
        }

        body.status-danger .shield-scan {
            animation-duration: 1.1s;
        }

        body.status-danger .shield-ring {
            animation-duration: 1.4s;
        }

        .shield-visual.bursting .shield-burst {
            animation: burst 0.8s ease-out forwards;
        }

        .result-field {
            margin-bottom: 1.5rem;
        }

        .decision-panel {
            margin-top: 0.9rem;
            padding: 1rem;
            border-radius: 12px;
            background: rgba(100, 116, 139, 0.12);
            border: 1px solid rgba(100, 116, 139, 0.18);
        }

        .result-field label,
        .dashboard-card label {
            font-weight: 800;
            color: #000000;
            display: block;
            margin-bottom: 0.5rem;
        }

        .result-value {
            font-size: 1.1rem;
            color: #333;
        }

        .badge {
            display: inline-block;
            padding: 0.4rem 1rem;
            border-radius: 20px;
            font-size: 0.95rem;
            font-weight: 600;
        }

        .badge.safe {
            background: #c6f6d5;
            color: #22543d;
        }

        .badge.phishing {
            background: #fed7d7;
            color: #742a2a;
        }

        .badge.suspicious {
            background: #feebc8;
            color: #7c2d12;
        }

        .scan-helper {
            margin-bottom: 0.9rem;
            color: #475569;
            font-size: 0.96rem;
        }

        .trust-indicators {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 0.8rem;
        }

        .trust-chip {
            background: #e2e8f0;
            color: #334155;
            border: 1px solid #cbd5e1;
            padding: 0.35rem 0.7rem;
            border-radius: 999px;
            font-size: 0.82rem;
            font-weight: 600;
        }

        .analysis-layout {
            display: grid;
            grid-template-columns: minmax(0, 1fr);
            gap: 1rem;
            align-items: start;
            transition: grid-template-columns 0.35s ease;
        }

        .analysis-layout.assistant-open {
            grid-template-columns: minmax(0, 1.6fr) minmax(0, 1fr);
        }

        .assistant-column {
            opacity: 0;
            transform: translateX(18px);
            pointer-events: none;
            max-height: 0;
            overflow: hidden;
            transition: opacity 0.35s ease, transform 0.35s ease, max-height 0.35s ease;
        }

        .analysis-layout.assistant-open .assistant-column {
            opacity: 1;
            transform: translateX(0);
            pointer-events: auto;
            max-height: 2000px;
            overflow: visible;
        }

        .assistant-toggle-btn {
            display: flex;
            align-items: center;
            justify-content: flex-start;
            gap: 10px;
            padding: 12px 16px;
            min-height: 58px;
            border-radius: 999px;
            border: none;
            background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
            color: #ffffff;
            cursor: pointer;
            font: inherit;
            font-weight: 700;
            line-height: 1;
            letter-spacing: 0;
            transition: transform 0.2s ease, box-shadow 0.2s ease, opacity 0.2s ease;
            box-shadow: 0 12px 30px rgba(37, 99, 235, 0.35);
        }

        .assistant-toggle-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 16px 36px rgba(37, 99, 235, 0.45);
        }

        .assistant-toggle-btn:disabled {
            cursor: not-allowed;
            opacity: 0.65;
            transform: none;
            box-shadow: 0 8px 20px rgba(37, 99, 235, 0.22);
        }

        .assistant-toggle-btn .toggle-icon {
            display: flex;
            align-items: center;
            justify-content: center;
            flex: 0 0 auto;
            line-height: 0;
        }

        .assistant-toggle-btn:focus-visible {
            outline: 3px solid rgba(147, 197, 253, 0.65);
            outline-offset: 3px;
        }

        .dashboard-card {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 14px;
            padding: 1.25rem;
            box-shadow: 0 6px 14px rgba(15, 23, 42, 0.07);
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 0.85rem;
            margin-bottom: 0.9rem;
        }

        .summary-card .summary-label {
            font-size: 0.82rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #64748b;
            margin-bottom: 0.35rem;
            font-weight: 700;
        }

        .summary-card .summary-value {
            font-weight: 700;
            color: #0f172a;
            font-size: 1.06rem;
            line-height: 1.35;
        }

        .summary-card .summary-value.large {
            font-size: 1.4rem;
            color: #1d4ed8;
        }

        .incident-text {
            font-size: 1.02rem;
            line-height: 1.6;
            color: #334155;
        }

        .action-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 0.85rem;
        }

        .action-card h4 {
            font-size: 1rem;
            font-weight: 800;
            margin-bottom: 0.5rem;
            color: #000000;
        }

        .action-card ul {
            margin: 0;
            padding-left: 1rem;
            line-height: 1.6;
            color: #334155;
            font-size: 0.97rem;
        }

        .action-card li {
            margin-bottom: 0.5rem;
        }

        .technical-details summary {
            list-style: none;
            display: inline-flex;
            align-items: center;
            gap: 0.45rem;
            font-weight: 700;
            color: #1e3a8a;
            cursor: pointer;
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            border-radius: 10px;
            padding: 0.5rem 0.75rem;
        }

        .technical-details summary::-webkit-details-marker {
            display: none;
        }

        .technical-json {
            margin-top: 0.75rem;
            white-space: pre-wrap;
            word-wrap: break-word;
            background: #0f172a;
            color: #e2e8f0;
            border-radius: 12px;
            border: 1px solid #1e293b;
            padding: 0.9rem;
            font-family: Consolas, Monaco, monospace;
            font-size: 0.84rem;
        }

        .result-meta {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 1rem;
            margin-top: 0.9rem;
        }

        .download-report-btn {
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
        }

        .download-report-btn.is-loading {
            background: #1e3a8a !important;
            opacity: 0.92;
        }

        .download-report-btn.is-success {
            background: #15803d !important;
        }

        .fade-card {
            opacity: 0;
            transform: translateY(10px);
        }

        .analysis-result.show .fade-card {
            animation: fadeInUp 0.45s ease forwards;
        }

        .analysis-result.show .fade-card:nth-child(2) { animation-delay: 0.08s; }
        .analysis-result.show .fade-card:nth-child(3) { animation-delay: 0.14s; }
        .analysis-result.show .fade-card:nth-child(4) { animation-delay: 0.2s; }

        .dashboard-layout {
            display: grid;
            grid-template-columns: 220px minmax(0, 1fr);
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .dashboard-nav {
            background: #0f2747;
            border: 1px solid rgba(191, 219, 254, 0.25);
            border-radius: 16px;
            padding: 0.8rem;
            position: sticky;
            top: 90px;
            height: fit-content;
            box-shadow: 0 10px 24px rgba(8, 21, 39, 0.28);
        }

        .dashboard-tab-btn {
            width: 100%;
            border: 1px solid transparent;
            background: transparent;
            color: #dbeafe;
            padding: 0.78rem 0.75rem;
            border-radius: 12px;
            text-align: left;
            font-weight: 600;
            cursor: pointer;
            margin-bottom: 0.45rem;
            transition: background 0.2s ease, color 0.2s ease, border-color 0.2s ease;
        }

        .dashboard-tab-btn:hover {
            background: rgba(59, 130, 246, 0.2);
        }

        .dashboard-tab-btn.active {
            background: #1d4ed8;
            color: #ffffff;
            border-color: rgba(191, 219, 254, 0.5);
        }

        .dashboard-tab-btn .tab-icon {
            margin-right: 0.5rem;
        }

        .dashboard-tab-panel {
            display: none;
        }

        .dashboard-tab-panel.active {
            display: block;
            animation: fadeInUp 0.26s ease both;
        }

        .settings-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 1rem;
        }

        .settings-card {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 16px;
            padding: 1.1rem;
            box-shadow: 0 12px 28px rgba(15, 23, 42, 0.08);
        }

        .settings-card h3 {
            font-size: 1rem;
            margin: 0 0 0.9rem;
            color: #0b1f3a;
        }

        .settings-card label {
            font-weight: 700;
            color: #334155;
        }

        .settings-card input,
        .settings-card select {
            width: 100%;
            min-height: 42px;
            border: 1px solid #cbd5e1;
            border-radius: 10px;
            background: #f8fafc;
            color: #0f172a;
            font: inherit;
            padding: 0.62rem 0.75rem;
            transition: border-color 0.18s ease, box-shadow 0.18s ease, background 0.18s ease;
        }

        .settings-card input:focus,
        .settings-card select:focus {
            outline: none;
            border-color: #2563eb;
            background: #ffffff;
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.14);
        }

        .password-hold-field {
            display: grid;
            grid-template-columns: minmax(0, 1fr) auto;
            align-items: stretch;
            border: 1px solid #cbd5e1;
            border-radius: 10px;
            background: #f8fafc;
            overflow: hidden;
            transition: border-color 0.18s ease, box-shadow 0.18s ease, background 0.18s ease;
        }

        .password-hold-field:focus-within {
            border-color: #2563eb;
            background: #ffffff;
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.14);
        }

        .password-hold-field input {
            min-height: 42px;
            border: 0;
            border-radius: 0;
            background: transparent;
            box-shadow: none;
        }

        .password-hold-field input:focus {
            box-shadow: none;
            background: transparent;
        }

        .password-hold-btn {
            min-width: 72px;
            border: 0;
            border-left: 1px solid #cbd5e1;
            background: #e2e8f0;
            color: #000000;
            font: inherit;
            font-size: 0.82rem;
            font-weight: 800;
            cursor: pointer;
            padding: 0 0.8rem;
            display: inline-flex;
            align-items: center;
            justify-content: center;
        }

        .password-hold-btn:active,
        .password-hold-btn.is-holding {
            background: #bfdbfe;
            color: #000000;
        }

        .password-hold-btn svg {
            width: 20px;
            height: 20px;
            stroke: currentColor;
            pointer-events: none;
        }

        .avatar-wrap {
            display: flex;
            align-items: center;
            gap: 0.85rem;
        }

        .avatar-preview {
            width: 72px;
            height: 72px;
            border-radius: 999px;
            object-fit: cover;
            border: 2px solid #bfdbfe;
            background: #e2e8f0;
        }

        .settings-help {
            color: #64748b;
            font-size: 0.86rem;
            margin-top: 0.45rem;
        }

        .session-timeout-notice {
            position: fixed;
            inset: 0;
            background: rgba(8, 15, 35, 0.65);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 10000;
        }

        .session-timeout-notice.show {
            display: flex;
        }

        .session-timeout-card {
            background: #ffffff;
            border: 1px solid #cbd5e1;
            border-radius: 14px;
            padding: 1.2rem;
            max-width: 380px;
            box-shadow: 0 12px 26px rgba(15, 23, 42, 0.28);
        }

        .session-timeout-card h3 {
            margin: 0 0 0.45rem;
            color: #0b1f3a;
        }

        .scan-detail-modal {
            position: fixed;
            inset: 0;
            display: none;
            align-items: center;
            justify-content: center;
            padding: 1rem;
            background: rgba(8, 21, 39, 0.58);
            z-index: 10000;
        }

        .scan-detail-modal.show {
            display: flex;
        }

        .scan-detail-panel {
            width: min(780px, 100%);
            max-height: 84vh;
            overflow: auto;
            background: #ffffff;
            border: 1px solid #dbe4ef;
            border-radius: 14px;
            box-shadow: 0 24px 70px rgba(8, 21, 39, 0.35);
        }

        .scan-detail-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 1rem;
            padding: 1rem 1.15rem;
            background: #10294a;
            color: #ffffff;
        }

        .scan-detail-header h3 {
            margin: 0;
            font-size: 1rem;
        }

        .scan-detail-close {
            border: 1px solid rgba(255, 255, 255, 0.35);
            background: rgba(255, 255, 255, 0.12);
            color: #ffffff;
            border-radius: 8px;
            padding: 0.35rem 0.65rem;
            cursor: pointer;
            font-weight: 700;
        }

        .scan-detail-body {
            padding: 1.15rem;
            display: grid;
            gap: 1rem;
        }

        .scan-detail-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 0.8rem 1rem;
        }

        .scan-detail-row {
            display: grid;
            grid-template-columns: 132px minmax(0, 1fr);
            gap: 0.75rem;
            align-items: start;
            min-width: 0;
        }

        .scan-detail-row.full {
            grid-column: 1 / -1;
            grid-template-columns: 1fr;
            gap: 0.35rem;
            padding-top: 0.8rem;
            border-top: 1px solid #e2e8f0;
        }

        .scan-detail-row strong {
            color: #64748b;
            font-size: 0.86rem;
        }

        .scan-detail-row span,
        .scan-detail-row div,
        .scan-detail-row pre {
            margin: 0;
            color: #0f172a;
            white-space: pre-wrap;
            word-break: break-word;
            overflow-wrap: anywhere;
            font-family: inherit;
        }

        .scan-detail-url {
            display: block;
            max-width: 100%;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .scan-detail-tags {
            display: flex;
            gap: 0.45rem;
            flex-wrap: wrap;
        }

        .scan-detail-section-title {
            margin: 0 0 0.45rem;
            color: #0b1f3a;
            font-size: 0.92rem;
        }

        .scan-detail-subsection {
            display: grid;
            gap: 0.45rem;
        }

        body.pref-light-theme {
            background: radial-gradient(circle at top, #edf3ff 0%, #f8fafc 45%, #ffffff 100%);
            color: #0f172a;
        }

        body.pref-light-theme .dashboard-nav {
            background: #e8f0ff;
            border-color: #bfdbfe;
        }

        body.pref-light-theme .dashboard-tab-btn {
            color: #1e3a8a;
        }

        .form-error {
            color: #b91c1c;
            font-size: 0.84rem;
            margin-top: 0.45rem;
            display: none;
        }

        .settings-row {
            display: grid;
            gap: 0.5rem;
            margin-bottom: 0.8rem;
        }

        .history-action-btns {
            display: grid;
            grid-template-columns: 1fr;
            gap: 0.45rem;
            align-items: start;
        }

        .history-filter-grid {
            display: grid;
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .history-filter-grid.row-1 {
            grid-template-columns: minmax(240px, 1.5fr) minmax(160px, 0.8fr) minmax(160px, 0.8fr);
        }

        .history-filter-grid.row-2,
        .history-filter-grid.row-3 {
            grid-template-columns: repeat(2, minmax(160px, 1fr));
        }

        .history-filter-grid .form-group {
            margin-bottom: 0;
        }

        .history-filter-grid input,
        .history-filter-grid select {
            width: 100%;
            padding: 0.8rem;
            border: 1px solid #cbd5e1;
            border-radius: 12px;
            font-size: 1rem;
            font-family: inherit;
            background: #ffffff;
        }

        .history-pagination {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 1rem;
            flex-wrap: wrap;
            margin-top: 1rem;
        }

        .history-page-info {
            color: #64748b;
            font-size: 0.92rem;
            font-weight: 600;
        }

        .history-page-controls {
            display: flex;
            gap: 0.4rem;
            flex-wrap: wrap;
        }

        .page-btn {
            border: 1px solid #bfdbfe;
            border-radius: 8px;
            background: #eff6ff;
            color: #1e3a8a;
            padding: 0.42rem 0.7rem;
            font: inherit;
            font-size: 0.86rem;
            font-weight: 700;
            cursor: pointer;
        }

        .page-btn.active {
            background: #1d4ed8;
            color: #ffffff;
            border-color: #1d4ed8;
        }

        .page-btn:disabled {
            opacity: 0.55;
            cursor: not-allowed;
        }

        .btn-mini {
            border: 1px solid #cbd5e1;
            border-radius: 8px;
            padding: 0.42rem 0.65rem;
            background: #ffffff;
            color: #1e3a8a;
            font-size: 0.8rem;
            font-weight: 600;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 118px;
            min-height: 34px;
            line-height: 1.1;
            white-space: nowrap;
            text-align: center;
        }

        .btn-mini:disabled {
            opacity: 0.55;
            cursor: not-allowed;
        }

        .confidence-bar {
            width: 100%;
            height: 8px;
            background: #e0e0e0;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 0.5rem;
        }

        .confidence-fill {
            height: 100%;
            background: linear-gradient(90deg, #1b4f8a 0%, #d4a84a 100%);
            transition: width 0.3s ease;
        }

        .history-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }

        .history-table thead {
            background: #f7fafc;
            border-bottom: 2px solid #e2e8f0;
        }

        .history-table th {
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            color: #333;
        }

        .history-table td {
            padding: 1rem;
            border-bottom: 1px solid #e2e8f0;
        }

        .history-table tbody tr:hover {
            background: #f9fafb;
        }

        .history-table a {
            color: #667eea;
            text-decoration: none;
        }

        .history-table a:hover {
            text-decoration: underline;
        }

        .empty-state {
            text-align: center;
            padding: 3rem;
            color: #999;
        }

        .empty-state p {
            font-size: 1.1rem;
        }

        #clickedUrlModal {
            border: none;
            border-radius: 12px;
            padding: 0;
            max-width: 460px;
            width: calc(100% - 32px);
            box-shadow: 0 20px 40px rgba(15, 23, 42, 0.35);
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            margin: 0;
        }

        #clickedUrlModal::backdrop {
            background: rgba(11, 31, 58, 0.38);
            backdrop-filter: blur(6px);
            -webkit-backdrop-filter: blur(6px);
        }

        .sr-only {
            position: absolute;
            width: 1px;
            height: 1px;
            padding: 0;
            margin: -1px;
            overflow: hidden;
            clip: rect(0, 0, 0, 0);
            white-space: nowrap;
            border: 0;
        }

        .assistant-column {
            position: static;
            opacity: 1;
            transform: none;
            pointer-events: none;
            max-height: none;
            overflow: visible;
            transition: none;
        }

        .assistant-overlay {
            position: fixed;
            inset: 0;
            background: rgba(15, 23, 42, 0.55);
            backdrop-filter: blur(4px);
            -webkit-backdrop-filter: blur(4px);
            opacity: 0;
            visibility: hidden;
            pointer-events: none;
            z-index: 9998;
            transition: opacity 0.2s ease, visibility 0.2s ease;
        }

        .assistant-column.assistant-open {
            pointer-events: auto;
        }

        .assistant-column.assistant-open .assistant-overlay {
            opacity: 1;
            visibility: visible;
            pointer-events: auto;
        }

        .assistant-panel {
            position: fixed;
            right: 24px;
            bottom: 24px;
            width: 720px;
            max-width: calc(100vw - 32px);
            height: 80vh;
            max-height: calc(100vh - 48px);
            min-height: 520px;
            background: #ffffff;
            border: 1px solid rgba(219, 234, 254, 0.9);
            border-radius: 24px;
            overflow: hidden;
            box-shadow: 0 24px 60px rgba(15, 23, 42, 0.35);
            z-index: 9999;
            display: flex;
            flex-direction: column;
            opacity: 0;
            visibility: hidden;
            pointer-events: none;
            transform: translateY(18px) scale(0.98);
            transition: opacity 0.22s ease, transform 0.22s ease, visibility 0.22s ease;
        }

        .assistant-column.assistant-open .assistant-panel {
            opacity: 1;
            visibility: visible;
            pointer-events: auto;
            transform: translateY(0) scale(1);
        }

        .assistant-header {
            min-height: 88px;
            background: linear-gradient(135deg, #dbeafe 0%, #2563eb 100%);
            display: flex;
            align-items: center;
            gap: 14px;
            padding: 0 24px;
            border-bottom: 1px solid rgba(191, 219, 254, 0.6);
        }

        .assistant-close-btn {
            width: 38px;
            height: 38px;
            border-radius: 50%;
            border: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: rgba(255, 255, 255, 0.22);
            color: #0f172a;
            cursor: pointer;
            font: inherit;
            font-size: 1.5rem;
            line-height: 1;
            transition: transform 0.2s ease, background 0.2s ease;
        }

        .assistant-close-btn:hover {
            transform: translateY(-1px);
            background: rgba(255, 255, 255, 0.34);
        }

        .assistant-header-icon {
            width: 46px;
            height: 46px;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.24);
            color: #ffffff;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.26);
        }

        .assistant-header-copy {
            flex: 1;
            min-width: 0;
        }

        .assistant-header h3 {
            margin: 0 0 0.32rem;
            color: #ffffff;
            font-size: 1.18rem;
            line-height: 1.2;
        }

        .assistant-online-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
            color: #ecfeff;
            font-size: 0.86rem;
            font-weight: 700;
        }

        .assistant-online-badge::before {
            content: "";
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #22c55e;
            box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.24);
        }

        .assistant-body {
            flex: 1;
            min-height: 0;
            display: flex;
            flex-direction: column;
            background: #f8fafc;
        }

        .assistant-starters {
            padding: 18px 24px 12px;
            border-bottom: none;
            background: #f8fafc;
        }

        .assistant-question-panel {
            padding: 18px 24px 12px;
        }

        .assistant-messages {
            flex: 1;
            min-height: 0;
            max-height: none;
            padding: 18px 24px 24px;
            background: #f8fafc;
        }

        .assistant-input {
            padding: 20px;
            border-top: 1px solid #e5e7eb;
            background: #ffffff;
        }

        .assistant-category-bar {
            padding: 16px 20px;
        }

        #assistantInput {
            border-radius: 999px;
            border: 1px solid #cbd5e1;
            padding: 0.85rem 1rem;
            background: #ffffff;
        }

        .assistant-send {
            border-radius: 999px;
            min-width: 88px;
        }

        .floating-assistant-icon {
            position: fixed !important;
            top: auto !important;
            left: auto !important;
            right: 28px !important;
            bottom: 28px !important;
            width: 64px;
            height: 64px;
            min-height: 0;
            padding: 0;
            gap: 0;
            border-radius: 50%;
            border: none;
            background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
            color: #ffffff;
            box-shadow: 0 12px 30px rgba(37, 99, 235, 0.4);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            pointer-events: auto;
            z-index: 9999;
            transition: transform 0.2s ease, box-shadow 0.2s ease, opacity 0.2s ease;
        }

        .floating-assistant-icon:hover {
            transform: translateY(-3px) scale(1.04);
            box-shadow: 0 16px 36px rgba(37, 99, 235, 0.48);
        }

        @media (max-width: 768px) {
            .user-header {
                flex-direction: column;
                gap: 1rem;
                text-align: center;
            }

            .brand-title {
                font-size: 1.5rem;
            }

            .brand img {
                height: 200px;
            }

            .form-row {
                grid-template-columns: 1fr;
            }

            .history-filter-grid.row-1,
            .history-filter-grid.row-2,
            .history-filter-grid.row-3 {
                grid-template-columns: 1fr;
            }

            .stats-grid {
                grid-template-columns: 1fr;
            }

            .card {
                padding: 1.5rem;
            }

            .analysis-layout {
                grid-template-columns: 1fr;
            }

            .analysis-layout.assistant-open {
                grid-template-columns: 1fr;
            }

            .dashboard-layout {
                grid-template-columns: 1fr;
            }

            .dashboard-nav {
                position: static;
                display: flex;
                gap: 0.5rem;
                overflow-x: auto;
            }

            .dashboard-tab-btn {
                width: auto;
                margin-bottom: 0;
                white-space: nowrap;
            }

            .settings-grid {
                grid-template-columns: 1fr;
            }

            .scan-detail-grid {
                grid-template-columns: 1fr;
            }

            .scan-detail-row {
                grid-template-columns: 1fr;
                gap: 0.25rem;
            }

            .scan-detail-url {
                white-space: normal;
                word-break: break-all;
            }

            .assistant-column {
                transform: translateY(8px);
            }

            .analysis-layout.assistant-open .assistant-column {
                transform: translateY(0);
            }

            .assistant-panel {
                right: 0;
                bottom: 0;
                width: 100%;
                max-width: 100%;
                height: 90vh;
                min-height: 0;
                border-radius: 24px 24px 0 0;
            }

            .assistant-header {
                padding: 0 16px;
            }

            .assistant-starters {
                padding: 16px 16px 10px;
            }

            .assistant-question-panel {
                padding: 16px 16px 10px;
            }

            .assistant-messages {
                padding: 16px;
            }

            .assistant-input {
                grid-template-columns: 1fr;
                padding: 16px;
            }

            .assistant-category-bar {
                padding: 14px 16px 16px;
            }

            .floating-assistant-icon {
                right: 18px;
                bottom: 18px;
                width: 58px;
                height: 58px;
            }

            .summary-grid,
            .action-grid {
                grid-template-columns: 1fr;
            }

            .result-meta {
                flex-direction: column;
                align-items: flex-start;
            }
        }
    </style>
</head>

<body class="<?php echo $show_transition ? 'has-transition' : ''; ?>">
    <?php if ($show_transition): ?>
        <div class="transition-overlay" id="transitionOverlay">
            <div class="transition-ring"></div>
            <div class="transition-shield">
                <div class="transition-scan"></div>
                <div class="transition-label">Shield</div>
            </div>
        </div>
    <?php endif; ?>
    <div class="user-header">
        <div class="brand">
            <img src="img/logo.png" alt="ShieldURL logo">
            <span class="brand-title">ShieldURL</span>
        </div>
        <div class="user-info">
            <div class="user-profile-chip">
                <img id="headerProfilePhoto" class="header-avatar" src="img/logo.png" alt="Profile photo">
                <span class="welcome-text">Welcome, <strong id="headerDisplayName"><?php echo htmlspecialchars($_SESSION['username']); ?></strong></span>
            </div>
            <a class="logout-btn" href="auth/logout.php">Logout</a>
        </div>
    </div>
    <div class="header-spacer" aria-hidden="true"></div>

    <div class="container">
        <section class="intro-hero">
            <div class="intro-card">
                <img class="intro-logo" src="img/logo.png" alt="ShieldURL logo">
                <h2 class="intro-title">ShieldURL</h2>
                <p class="intro-subtitle">A secure gateway that analyzes URLs, blocks phishing attempts, and keeps your browsing shielded.</p>
                <a class="intro-cta" href="#check-url">Scroll to Check URL</a>
                <div class="intro-hint">Protection starts below</div>
            </div>
        </section>
        <!-- Statistics -->
        <div class="stats-grid">
            <div class="stat-card">
                <h3>URLs Checked</h3>
                <div class="number"><?php echo (int)($total_checks ?? 0); ?></div>
            </div>
            <div class="stat-card">
                <h3>Safe URLs</h3>
                <div class="number" style="color: #48bb78;"><?php echo (int)($safe_count ?? 0); ?></div>
            </div>
            <div class="stat-card">
                <h3>Phishing</h3>
                <div class="number" style="color: #f56565;"><?php echo (int)($phishing_count ?? 0); ?></div>
            </div>
        </div>

        <div class="dashboard-layout">
            <aside class="dashboard-nav">
                <button class="dashboard-tab-btn active" data-tab-target="tab-check-url"><span class="tab-icon">🛡️</span>Check URL</button>
                <button class="dashboard-tab-btn" data-tab-target="tab-history"><span class="tab-icon">🕒</span>History</button>
                <button class="dashboard-tab-btn" data-tab-target="tab-settings"><span class="tab-icon">⚙️</span>Settings</button>
            </aside>

            <section>
                <div class="dashboard-tab-panel active" id="tab-check-url">
<?php require __DIR__ . '/shared/check_url_component.php'; ?>
                </div>

                <div class="dashboard-tab-panel" id="tab-history">
                    <div class="card">
                        <h2>Scan History</h2>
                        <div class="history-filter-grid row-1">
                            <div class="form-group">
                                <label for="historySearch">Search URL or Domain</label>
                                <input type="search" id="historySearch" placeholder="Search by URL or domain">
                            </div>
                            <div class="form-group">
                                <label for="historyFilter">Status</label>
                                <select id="historyFilter">
                                    <option value="">All</option>
                                    <option value="safe">Safe</option>
                                    <option value="phishing">Phishing</option>
                                    <option value="suspicious">Suspicious</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="historySort">Sort By</label>
                                <select id="historySort">
                                    <option value="newest">Newest First</option>
                                    <option value="oldest">Oldest First</option>
                                </select>
                            </div>
                        </div>
                        <div class="history-filter-grid row-2">
                            <div class="form-group">
                                <label for="historyDateFrom">From Date</label>
                                <input type="date" id="historyDateFrom">
                            </div>
                            <div class="form-group">
                                <label for="historyDateTo">To Date</label>
                                <input type="date" id="historyDateTo">
                            </div>
                        </div>
                        <div class="history-filter-grid row-3">
                            <button class="btn-check" id="historyRefreshBtn" type="button">Refresh</button>
                            <button class="btn-check" id="historyResetBtn" type="button">Reset Filters</button>
                        </div>

                        <div class="table-wrapper">
                            <table class="history-table">
                                <thead>
                                    <tr>
                                        <th>Date/Time</th>
                                        <th>Checked URL</th>
                                        <th>Status</th>
                                        <th>Confidence Score</th>
                                        <th>Risk Level</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody id="historyTableBody">
                                    <tr>
                                        <td colspan="6" class="empty-state">
                                            <p>No scan history available yet.</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                        <div class="history-pagination">
                            <div class="history-page-info" id="historyPageInfo">Showing 0 of 0 scans</div>
                            <div class="history-page-controls" id="historyPageControls"></div>
                        </div>
                    </div>
                </div>

                <div class="dashboard-tab-panel" id="tab-settings">
                    <div class="card">
                        <h2>Settings</h2>
                        <div class="settings-grid">
                            <div class="settings-card">
                                <h3>Profile Photo</h3>
                                <div class="avatar-wrap">
                                    <img id="profilePhotoPreview" class="avatar-preview" src="img/logo.png" alt="Profile photo preview">
                                    <div>
                                        <label for="profilePhotoInput" class="btn-check" style="display: inline-block; padding: 0.55rem 0.85rem; color: #ffffff;">Upload Photo</label>
                                        <input type="file" id="profilePhotoInput" accept=".jpg,.jpeg,.png" style="display:none;">
                                        <div class="settings-help">Accepted: JPG, JPEG, PNG. Preview only.</div>
                                        <div class="form-error" id="profilePhotoError"></div>
                                    </div>
                                </div>
                            </div>

                            <div class="settings-card">
                                <h3>Account Information</h3>
                                <div class="settings-row"><strong>Username</strong><span><?php echo htmlspecialchars($_SESSION['username']); ?></span></div>
                                <div class="settings-row"><strong>Email</strong><span><?php echo htmlspecialchars($_SESSION['email'] ?? 'Not available'); ?></span></div>
                                <div class="settings-row"><strong>Role</strong><span><?php echo htmlspecialchars($_SESSION['role'] ?? 'User'); ?></span></div>
                                <div class="settings-row"><strong>Account Source</strong><span>Created by admin</span></div>
                                <div class="settings-row"><strong>Account Status</strong><span>Active</span></div>
                                <div class="settings-help">Normal users cannot self-register or delete accounts from this page.</div>
                            </div>

                            <div class="settings-card">
                                <h3>Change Password</h3>
                                <form id="changePasswordForm">
                                    <div class="settings-row">
                                        <label for="currentPassword">Current Password</label>
                                        <div class="password-hold-field">
                                            <input id="currentPassword" type="password" autocomplete="current-password">
                                            <button class="password-hold-btn" type="button" data-password-target="currentPassword" aria-label="Hold to view current password" title="Hold to view password">
                                                <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
                                                    <path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6Z"></path>
                                                    <circle cx="12" cy="12" r="3"></circle>
                                                </svg>
                                            </button>
                                        </div>
                                    </div>
                                    <div class="settings-row">
                                        <label for="newPassword">New Password</label>
                                        <div class="password-hold-field">
                                            <input id="newPassword" type="password" autocomplete="new-password">
                                            <button class="password-hold-btn" type="button" data-password-target="newPassword" aria-label="Hold to view new password" title="Hold to view password">
                                                <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
                                                    <path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6Z"></path>
                                                    <circle cx="12" cy="12" r="3"></circle>
                                                </svg>
                                            </button>
                                        </div>
                                    </div>
                                    <div class="settings-row">
                                        <label for="confirmPassword">Confirm New Password</label>
                                        <div class="password-hold-field">
                                            <input id="confirmPassword" type="password" autocomplete="new-password">
                                            <button class="password-hold-btn" type="button" data-password-target="confirmPassword" aria-label="Hold to view confirm password" title="Hold to view password">
                                                <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
                                                    <path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6Z"></path>
                                                    <circle cx="12" cy="12" r="3"></circle>
                                                </svg>
                                            </button>
                                        </div>
                                    </div>
                                    <button type="submit" class="btn-check" style="padding: 0.55rem 0.95rem;">Update Password</button>
                                    <div class="form-error" id="passwordError"></div>
                                    <div class="settings-help" id="passwordInfo"></div>
                                </form>
                            </div>

                            <div class="settings-card">
                                <h3>Preferences</h3>
                                <div class="settings-row">
                                    <label for="prefTheme">Theme</label>
                                    <select id="prefTheme">
                                        <option value="dark">Dark</option>
                                        <option value="light">Light</option>
                                    </select>
                                </div>
                                <div class="settings-row">
                                    <label for="prefHistory">Save Scan History</label>
                                    <select id="prefHistory">
                                        <option value="enabled">Enabled</option>
                                        <option value="disabled">Disabled</option>
                                    </select>
                                    <div class="settings-help">If disabled, new scans are not added to local quick history.</div>
                                </div>
                                <div class="settings-row">
                                    <label for="prefTechnical">Technical Details</label>
                                    <select id="prefTechnical">
                                        <option value="collapsed">Collapsed by default</option>
                                        <option value="expanded">Expanded by default</option>
                                    </select>
                                </div>
                                <button id="savePreferencesBtn" class="btn-check" type="button" style="padding: 0.55rem 0.95rem;">Save Preferences</button>
                                <div class="settings-help" id="prefInfo"></div>
                            </div>

                            <div class="settings-card">
                                <h3>Session Timeout</h3>
                                <div class="settings-row">
                                    <label for="prefSessionTimeout">Auto logout after inactivity</label>
                                    <select id="prefSessionTimeout">
                                        <option value="15">15 minutes</option>
                                        <option value="30">30 minutes</option>
                                        <option value="60">1 hour</option>
                                    </select>
                                    <div class="settings-help">For security, your session ends after inactivity.</div>
                                </div>
                            </div>

                        </div>
                    </div>
                </div>
            </section>
        </div>
    </div>

    <div id="sessionTimeoutNotice" class="session-timeout-notice" role="alertdialog" aria-modal="true" aria-labelledby="sessionTimeoutTitle">
        <div class="session-timeout-card">
            <h3 id="sessionTimeoutTitle">Session expired</h3>
            <p>Your session has expired due to inactivity.</p>
            <button id="sessionTimeoutOkBtn" class="btn-check" type="button" style="padding: 0.5rem 0.95rem;">Go to login</button>
        </div>
    </div>

    <div class="scan-detail-modal" id="scanDetailModal" aria-hidden="true">
        <div class="scan-detail-panel" role="dialog" aria-modal="true" aria-labelledby="scanDetailTitle">
            <div class="scan-detail-header">
                <h3 id="scanDetailTitle">Scan Result Details</h3>
                <button class="scan-detail-close" id="scanDetailCloseBtn" type="button">Close</button>
            </div>
            <div class="scan-detail-body" id="scanDetailBody"></div>
        </div>
    </div>

    <script>
        async function parseJsonResponse(response) {
            const text = await response.text();
            console.log('Response status:', response.status, response.statusText);
            console.log('Raw response:', text);

            let data = null;
            if (text.trim() !== '') {
                try {
                    data = JSON.parse(text);
                } catch (error) {
                    console.error('JSON parse error:', error, text);
                    throw new Error('Backend did not return valid JSON: ' + text);
                }
            }

            if (!response.ok) {
                throw new Error(
                    (data && (data.error || data.detail || data.message)) ||
                    ('Request failed with status ' + response.status)
                );
            }

            return data;
        }

        async function checkSessionBeforeAction(event) {
        try {
        const response = await fetch('api/check_session.php', {
            cache: 'no-store'
        });

        const data = await response.json();

        if (!data.valid) {
            event.preventDefault();
            event.stopPropagation();

            alert('Session has destroyed. Please login.');
            window.location.href = 'auth/login.php?err=session_destroyed';
            return false;
        }
        } catch (error) {
        event.preventDefault();
        alert('Session has destroyed. Please login.');
        window.location.href = 'auth/login.php?err=session_destroyed';
        return false;
         }
           }

        // check session whenever user clicks anything important
        document.addEventListener('click', function(event) {
        const target = event.target.closest('button, a, input[type="submit"]');

        if (target) {
           checkSessionBeforeAction(event);
        }
        }, true);

        function askClickedStatus() {
            const modal = document.getElementById('clickedUrlModal');
            const yesBtn = document.getElementById('clickedYesBtn');
            const noBtn = document.getElementById('clickedNoBtn');

            if (!modal || typeof modal.showModal !== 'function' || !yesBtn || !noBtn) {
                return Promise.resolve(window.confirm('Have you already clicked this URL?'));
            }

            return new Promise((resolve) => {
                const onYes = () => {
                    cleanup();
                    modal.close();
                    resolve(true);
                };
                const onNo = () => {
                    cleanup();
                    modal.close();
                    resolve(false);
                };
                const onCancel = () => {
                    cleanup();
                    resolve(false);
                };
                const cleanup = () => {
                    yesBtn.removeEventListener('click', onYes);
                    noBtn.removeEventListener('click', onNo);
                    modal.removeEventListener('cancel', onCancel);
                };

                yesBtn.addEventListener('click', onYes);
                noBtn.addEventListener('click', onNo);
                modal.addEventListener('cancel', onCancel);
                modal.showModal();
            });
        }

        let currentScanId = null;
        let currentScanContext = null;
        let assistantIsLoading = false;
        let assistantPanelOpen = false;
        let hasScanResult = false;
        let isScanRunning = false;
        let localScanHistory = [];
        const scanResultSnapshots = {};
        let inactivityTimeoutId = null;
        let sessionExpiredShown = false;
        let historyRowsCache = [];
        let historyCurrentPage = 1;
        const historyPageSize = 10;
        const profilePhotoStorageKey = 'shieldurl_profile_photo_dataurl_<?php echo (int)$_SESSION['user_id']; ?>';
        const currentUsername = <?php echo json_encode($_SESSION['username'] ?? ''); ?>;

        function mapRiskFromStatus(status) {
            const normalized = String(status || '').toLowerCase();
            if (normalized === 'phishing') return 'High Risk';
            if (normalized === 'suspicious' || normalized.includes('suspicious')) return 'Medium Risk';
            return 'Low Risk';
        }

        function getPreference(key, fallback) {
            const value = localStorage.getItem(key);
            return value === null || value === '' ? fallback : value;
        }

        function getSessionTimeoutMs() {
            const minutes = Number(getPreference('shieldurl_pref_session_timeout_minutes', '30'));
            const safeMinutes = [15, 30, 60].includes(minutes) ? minutes : 30;
            return safeMinutes * 60 * 1000;
        }

        function scheduleInactivityTimeout() {
            if (inactivityTimeoutId) {
                clearTimeout(inactivityTimeoutId);
            }
            inactivityTimeoutId = setTimeout(() => {
                if (isScanRunning) {
                    scheduleInactivityTimeout();
                    return;
                }
                if (sessionExpiredShown) {
                    return;
                }
                sessionExpiredShown = true;
                const notice = document.getElementById('sessionTimeoutNotice');
                if (notice) {
                    notice.classList.add('show');
                } else {
                    alert('Your session has expired due to inactivity.');
                    window.location.href = 'auth/logout.php';
                }
            }, getSessionTimeoutMs());
        }

        function updateHeaderProfilePhoto(photoDataUrl) {
            const fallback = 'img/logo.png';
            const src = photoDataUrl || fallback;
            const headerPhoto = document.getElementById('headerProfilePhoto');
            const settingsPhoto = document.getElementById('profilePhotoPreview');
            if (headerPhoto) headerPhoto.src = src;
            if (settingsPhoto) settingsPhoto.src = src;
        }

        function escapeHtml(value) {
            return String(value ?? '')
                .replaceAll('&', '&amp;')
                .replaceAll('<', '&lt;')
                .replaceAll('>', '&gt;')
                .replaceAll('"', '&quot;')
                .replaceAll("'", '&#39;');
        }

        function setScanButtonLabel(label) {
            const btn = document.getElementById('scanActionBtn');
            if (btn) {
                btn.textContent = label;
            }
        }

        function setScanInteractionState({ inputDisabled, buttonDisabled, buttonLabel }) {
            const urlInput = document.getElementById('url');
            const scanBtn = document.getElementById('scanActionBtn');
            if (urlInput) {
                urlInput.disabled = Boolean(inputDisabled);
            }
            if (scanBtn) {
                scanBtn.disabled = Boolean(buttonDisabled);
                scanBtn.textContent = buttonLabel;
            }
        }

        function resetScanViewForRecheck() {
            const analysisResult = document.getElementById('analysisResult');
            const resultDiv = document.getElementById('checkResult');
            const urlInput = document.getElementById('url');
            if (analysisResult) {
                analysisResult.classList.remove('show');
            }
            if (resultDiv) {
                resultDiv.className = 'result-message';
                resultDiv.textContent = '';
            }
            resetAssistant(null);
            hasScanResult = false;
            isScanRunning = false;
            setScanInteractionState({
                inputDisabled: false,
                buttonDisabled: false,
                buttonLabel: 'Scan URL'
            });
            if (urlInput) {
                urlInput.value = '';
                urlInput.focus();
            }
        }

        function captureCurrentResultSnapshot(reportUrl) {
            const key = `local-${Date.now()}`;
            scanResultSnapshots[key] = {
                statusBadgeClass: document.getElementById('statusBadge').className,
                statusText: document.getElementById('statusBadge').textContent,
                confidenceText: document.getElementById('confidenceScore').textContent,
                confidenceWidth: document.getElementById('confidenceFill').style.width,
                riskText: document.getElementById('riskLevelValue').textContent,
                mitrePrimary: document.getElementById('mitrePrimaryValue').textContent,
                interactionStatus: document.getElementById('interactionStatusValue')?.textContent || 'Not collected',
                resultUrlHref: document.getElementById('resultUrl').href,
                resultUrlText: document.getElementById('resultUrl').textContent,
                modelPhishingProbability: document.getElementById('modelPhishingProbability').textContent,
                modelSelectedThreshold: document.getElementById('modelSelectedThreshold').textContent,
                modelFinalVerdict: document.getElementById('modelFinalVerdict').textContent,
                modelDisplayVerdict: document.getElementById('modelDisplayVerdict').textContent,
                modelPolicyText: document.getElementById('modelPolicyText').textContent,
                incidentSummary: document.getElementById('llmSummary').textContent,
                analyzedTime: document.getElementById('analyzedTime').textContent,
                analysisDetails: document.getElementById('analysisDetails').textContent,
                userAdvisory: document.getElementById('userAdvisory').textContent,
                containmentItems: Array.from(document.querySelectorAll('#containmentList li')).map(li => li.textContent),
                eradicationItems: Array.from(document.querySelectorAll('#eradicationList li')).map(li => li.textContent),
                postIncidentItems: Array.from(document.querySelectorAll('#postIncidentList li')).map(li => li.textContent),
                mitreTags: Array.from(document.querySelectorAll('#mitreTags .badge')).map(tag => tag.textContent),
                reportUrl: reportUrl || '',
                scanContext: currentScanContext,
                reportId: currentScanId
            };
            return key;
        }

        function renderSimpleListFromSnapshot(containerId, items, fallbackText) {
            const container = document.getElementById(containerId);
            if (!container) return;
            const card = container.closest('.action-card');
            container.innerHTML = '';
            items = dedupeRenderItems(items || []);
            if (!items.length) {
                if (card) card.style.display = 'none';
                return;
            }
            if (card) card.style.display = '';
            items.forEach(text => {
                const li = document.createElement('li');
                li.textContent = text;
                container.appendChild(li);
            });
        }

        function applyResultSnapshot(snapshotKey) {
            const snap = scanResultSnapshots[snapshotKey];
            if (!snap) return;
            document.getElementById('statusBadge').className = snap.statusBadgeClass;
            document.getElementById('statusBadge').textContent = snap.statusText;
            document.getElementById('confidenceScore').textContent = snap.confidenceText;
            document.getElementById('confidenceFill').style.width = snap.confidenceWidth;
            document.getElementById('riskLevelValue').textContent = snap.riskText;
            updateMitreSummary('', String(snap.statusText || '').toLowerCase().includes('safe') ? 'safe' : '', snap.mitrePrimary);
            if (document.getElementById('interactionStatusValue')) document.getElementById('interactionStatusValue').textContent = snap.interactionStatus || 'Not collected';
            document.getElementById('resultUrl').href = snap.resultUrlHref;
            document.getElementById('resultUrl').textContent = snap.resultUrlText;
            document.getElementById('modelPhishingProbability').textContent = snap.modelPhishingProbability || 'Not Collected';
            document.getElementById('modelSelectedThreshold').textContent = snap.modelSelectedThreshold || 'Not Collected';
            document.getElementById('modelFinalVerdict').textContent = snap.modelFinalVerdict || 'UNKNOWN';
            document.getElementById('modelDisplayVerdict').textContent = snap.modelDisplayVerdict || 'UNKNOWN';
            document.getElementById('modelPolicyText').textContent = simplePolicyText(snap.modelPolicyText);
            document.getElementById('llmSummary').textContent = snap.incidentSummary;
            document.getElementById('analyzedTime').textContent = snap.analyzedTime;
            document.getElementById('analysisDetails').textContent = snap.analysisDetails;
            document.getElementById('userAdvisory').textContent = snap.userAdvisory;
            renderSimpleListFromSnapshot('containmentList', snap.containmentItems, '');
            renderSimpleListFromSnapshot('eradicationList', snap.eradicationItems, '');
            renderSimpleListFromSnapshot('postIncidentList', snap.postIncidentItems, '');
            const mitreContainer = document.getElementById('mitreTags');
            mitreContainer.innerHTML = '';
            (snap.mitreTags || []).forEach(text => {
                const span = document.createElement('span');
                span.className = 'badge';
                span.style.background = '#e2e8f0';
                span.style.color = '#4a5568';
                span.textContent = text;
                mitreContainer.appendChild(span);
            });
            const downloadBtn = document.getElementById('downloadReportBtn');
            const downloadLabel = document.getElementById('downloadReportLabel');
            if (snap.reportUrl) {
                downloadBtn.href = snap.reportUrl;
                downloadBtn.style.display = 'inline-flex';
                downloadLabel.textContent = 'Download Report';
            } else {
                downloadBtn.style.display = 'none';
            }
            document.getElementById('analysisResult').classList.add('show');
            resetAssistant(snap.reportId || null, snap.scanContext || null);
            hasScanResult = true;
            isScanRunning = false;
            setScanInteractionState({
                inputDisabled: true,
                buttonDisabled: false,
                buttonLabel: 'Recheck URL'
            });
            const resultDiv = document.getElementById('checkResult');
            resultDiv.className = 'result-message success';
            resultDiv.textContent = 'Showing result from history.';
        }

        function switchDashboardTab(tabId) {
            document.querySelectorAll('.dashboard-tab-btn').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.tabTarget === tabId);
            });
            document.querySelectorAll('.dashboard-tab-panel').forEach(panel => {
                panel.classList.toggle('active', panel.id === tabId);
            });
            if (tabId === 'tab-history') {
                loadHistory();
            }
        }

        function normalizeToList(value) {
            if (Array.isArray(value)) return value.filter(v => v !== null && v !== undefined && String(v).trim() !== '');
            if (typeof value === 'string' && value.trim() !== '') return [value.trim()];
            return [];
        }

        function displayValue(value) {
            if (value === null || value === undefined || String(value).trim() === '') return 'Not Collected';
            return String(value);
        }

        function displayNetworkValue(value, type) {
            if (value === null || value === undefined || String(value).trim() === '') {
                return type === 'country' ? 'Private Network' : 'Local Session';
            }
            const normalized = String(value).trim();
            if (['Local/Private', 'localhost', '127.0.0.1', '::1'].includes(normalized)) {
                return type === 'country' ? 'Private Network' : 'Local Session';
            }
            return normalized;
        }

        function formatConfidenceValue(value) {
            if (typeof value === 'string' && value.includes('%')) return value;
            const numeric = Number(value || 0);
            const percent = numeric <= 1 ? numeric * 100 : numeric;
            return Number.isFinite(percent) ? percent.toFixed(2) + '%' : 'Not Collected';
        }

        function simplePolicyText(value) {
            const text = String(value || '').trim();
            if (!text || /lexical model|false negatives|threshold|recall/i.test(text)) {
                return 'No major phishing indicators were identified during analysis.';
            }
            return text;
        }

        function dedupeRenderItems(items) {
            const seen = new Set();
            return (items || []).filter(item => {
                const key = String(item || '').trim().toLowerCase();
                if (!key || seen.has(key)) return false;
                seen.add(key);
                return true;
            });
        }

        function verdictPolicyText(displayVerdict, fallback) {
            const verdict = String(displayVerdict || '').toLowerCase();
            if (verdict.includes('phishing') && !verdict.includes('suspicious')) {
                return 'Phishing was detected by the URL model; confidence and risk level determine response severity.';
            }
            if (verdict.includes('suspicious')) {
                return 'Several suspicious URL characteristics were identified during analysis.';
            }
            return simplePolicyText(fallback || 'No major phishing indicators were identified during analysis.');
        }

        function updateModelDecisionExplanation(data) {
            const probability = data?.phishing_probability ?? data?.ml?.phishing_probability ?? data?.detection?.phishing_probability ?? data?.confidence_score ?? data?.detection?.confidence_score;
            const threshold = data?.selected_threshold ?? data?.ml?.selected_threshold ?? data?.detection?.lexical_threshold;
            const finalVerdict = data?.status ?? data?.detection?.final_verdict ?? data?.overall?.status ?? 'unknown';
            const displayVerdict = data?.display_status ?? data?.overall?.display_verdict ?? data?.detection?.display_verdict ?? finalVerdict;
            const policy = verdictPolicyText(displayVerdict, data?.model_policy ?? data?.overall?.model_policy ?? data?.ml?.model_policy ?? data?.detection?.model_policy);

            document.getElementById('modelPhishingProbability').textContent = formatConfidenceValue(probability);
            document.getElementById('modelSelectedThreshold').textContent = threshold === undefined || threshold === null || threshold === '' ? 'Not Collected' : formatConfidenceValue(threshold);
            document.getElementById('modelFinalVerdict').textContent = String(finalVerdict).replaceAll('_', ' ').toUpperCase();
            document.getElementById('modelDisplayVerdict').textContent = String(displayVerdict).replaceAll('_', ' ').toUpperCase();
            document.getElementById('modelPolicyText').textContent = policy;
        }

        function updateActionTitles(audience) {
            const isAdmin = String(audience || '').toLowerCase() === 'admin';
            const labels = isAdmin
                ? ['Containment', 'Eradication & Recovery', 'Post-Incident Recommendations']
                : ['Recommended Actions', 'Follow-Up', 'Additional Guidance'];
            ['containmentTitle', 'eradicationTitle', 'postIncidentTitle'].forEach((id, index) => {
                const el = document.getElementById(id);
                if (el) el.textContent = labels[index];
            });
            document.getElementById('containmentTitle')?.classList.toggle('sr-only', !isAdmin);
        }

        function updateMitreSummary(audience, verdictMode, value) {
            const card = document.getElementById('mitreSummaryCard');
            const field = document.getElementById('mitrePrimaryValue');
            if (card) card.style.display = verdictMode === 'safe' ? 'none' : '';
            if (field) field.textContent = value || 'Not Applicable';
        }

        function formatScanDuration(value) {
            if (value === null || value === undefined || String(value).trim() === '') return 'Not Collected';
            const numeric = Number(value);
            if (!Number.isFinite(numeric)) return displayValue(value);
            return numeric.toFixed(1) + ' sec';
        }

        function formatMitreTags(items) {
            const list = normalizeToList(items);
            if (!list.length) return '<span>Not Collected</span>';
            return `<div class="scan-detail-tags">${list.map(item => {
                const label = typeof item === 'object'
                    ? `${item.id || item.technique_id || ''}${((item.id || item.technique_id) && (item.name || item.technique)) ? ' - ' : ''}${item.name || item.technique || item.description || 'Technique'}`
                    : item;
                return `<span class="badge">${escapeHtml(label)}</span>`;
            }).join('')}</div>`;
        }

        function formatActionList(items) {
            const list = normalizeToList(items);
            if (!list.length) return '<span>Not Collected</span>';
            return `<ul style="margin:0; padding-left:1.1rem;">${list.map(item => {
                const text = typeof item === 'object' ? (item.action || item.step || item.description || item.name || JSON.stringify(item)) : item;
                return `<li>${escapeHtml(text)}</li>`;
            }).join('')}</ul>`;
        }

        function scanDetailRow(label, value, full = false, extraClass = '') {
            return `
                <div class="scan-detail-row ${full ? 'full' : ''}">
                    <strong>${escapeHtml(label)}</strong>
                    ${full ? `<div class="${extraClass}">${value}</div>` : `<span class="${extraClass}">${value}</span>`}
                </div>
            `;
        }

        function parseFeaturePayload(features) {
            if (features && typeof features === 'object' && !Array.isArray(features)) return features;
            if (typeof features === 'string' && features.trim() !== '') {
                try {
                    return JSON.parse(features);
                } catch (error) {
                    return {};
                }
            }
            return {};
        }

        function featureSignal(features, keys) {
            for (const key of keys) {
                if (Object.prototype.hasOwnProperty.call(features, key)) {
                    const value = features[key];
                    const normalized = String(value).toLowerCase();
                    return value === -1 || normalized === 'detected' || normalized === 'yes' || normalized === 'true' || normalized === 'suspicious';
                }
            }
            return false;
        }

        function longUrlSignal(url, features) {
            if (String(url || '').length > 75) return true;
            for (const key of ['LongURL', 'URLURL_Length', 'URL_Length', 'url_length']) {
                if (!Object.prototype.hasOwnProperty.call(features, key)) continue;
                const value = features[key];
                const normalized = String(value).toLowerCase();
                if (typeof value === 'number') return value > 75 || value < 0;
                if (/^\d+(\.\d+)?$/.test(normalized)) return Number(normalized) > 75;
                return ['detected', 'yes', 'true', 'suspicious', 'long'].includes(normalized);
            }
            return false;
        }

        function scanEvidenceBadges(detail) {
            const url = String(detail.url || '');
            const features = parseFeaturePayload(detail.features || detail.analysisDetails);
            const lowerUrl = url.toLowerCase();
            const badges = [];
            let parsedUrl = null;
            try {
                parsedUrl = new URL(url.startsWith('http') ? url : 'http://' + url);
            } catch (error) {
                parsedUrl = null;
            }
            const protocol = parsedUrl ? parsedUrl.protocol.replace(':', '') : '';
            const hostParts = parsedUrl ? parsedUrl.hostname.split('.') : [];
            const tld = hostParts.length > 1 ? hostParts[hostParts.length - 1].toLowerCase() : '';
            const suspiciousTlds = ['zip', 'mov', 'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'icu', 'click', 'work'];
            const brandTerms = ['login', 'verify', 'secure', 'account', 'update', 'signin', 'wallet', 'bank', 'payment'];

            if (protocol && protocol !== 'https') badges.push('Non-HTTPS');
            if (tld && suspiciousTlds.includes(tld)) badges.push('Suspicious TLD');
            if (longUrlSignal(url, features)) badges.push('Long URL');
            if (brandTerms.some(term => lowerUrl.includes(term))) badges.push('Possible Brand Impersonation');

            if (!badges.length) return '<span>Not Collected</span>';
            return `<div class="scan-detail-tags">${badges.map(label => `<span class="badge suspicious">${escapeHtml(label)}</span>`).join('')}</div>`;
        }

        function threatBehaviorBullets(detail) {
            const status = String(detail.status || '').toLowerCase();
            const display = String(detail.display_status || detail.display_verdict || '').toLowerCase();
            const evidenceHtml = scanEvidenceBadges(detail);
            const evidenceLabels = Array.from(evidenceHtml.matchAll(/<span class="badge suspicious">([^<]+)<\/span>/g)).map(match => match[1]);
            const bullets = [];
            if (display.includes('suspicious')) bullets.push('Suspicious signals detected, but this URL is not confirmed as phishing.');
            else if (status === 'phishing') bullets.push('Likely credential harvesting or impersonation attempt.');
            if (status === 'suspicious') bullets.push('Suspicious URL indicators require review before user access.');
            if (evidenceLabels.includes('Non-HTTPS')) bullets.push('Connection does not use HTTPS.');
            if (evidenceLabels.includes('Possible Brand Impersonation')) bullets.push('URL contains terms commonly used in fake login or verification flows.');
            if (evidenceLabels.includes('Long URL')) bullets.push('URL length may be used to obscure destination or parameters.');
            if (!bullets.length) bullets.push('No high-risk behavior was collected from available scan details.');
            return bullets;
        }

        function openScanDetailModal(detail) {
            const modal = document.getElementById('scanDetailModal');
            const body = document.getElementById('scanDetailBody');
            const status = String(detail.status || detail.final_verdict || '').toUpperCase();
            const displayStatus = String(detail.display_status || detail.display_verdict || status);
            const displayClass = displayStatus.toLowerCase().includes('suspicious') ? 'suspicious' : String(detail.status || '').toLowerCase();
            const detailMode = displayStatus.toLowerCase().includes('suspicious') ? 'suspicious' : (String(detail.status || '').toLowerCase() === 'phishing' ? 'phishing' : 'safe');
            const nistActions = normalizeToList(detail.nist_response).length ? detail.nist_response : detail.incident_response;
            const checkedUrl = displayValue(detail.url);
            const summary = displayValue(detail.llm_summary || detail.incidentSummary);
            const behavior = threatBehaviorBullets(detail);
            body.innerHTML = `
                <div class="scan-detail-grid">
                    ${scanDetailRow('Timestamp', escapeHtml(displayValue(detail.analyzed_at || detail.timestamp)))}
                    ${scanDetailRow('User', escapeHtml(displayValue(detail.username || currentUsername)))}
                    ${scanDetailRow('Checked URL', `<span class="scan-detail-url" title="${escapeHtml(checkedUrl)}">${escapeHtml(checkedUrl)}</span>`)}
                    ${scanDetailRow('Safety Status', `<span class="badge ${escapeHtml(displayClass)}">${escapeHtml(displayValue(displayStatus).toUpperCase())}</span>`)}
                    ${scanDetailRow('System Detection', escapeHtml(displayValue(status)))}
                    ${scanDetailRow('Risk Level', escapeHtml(displayValue(detail.risk_level)))}
                    ${scanDetailRow('User Interaction Status', escapeHtml(displayValue(detail.user_interaction_status)))}
                    ${scanDetailRow('Confidence Score', escapeHtml(formatConfidenceValue(detail.confidence_score ?? detail.confidence)))}
                    ${scanDetailRow('Scan Duration', escapeHtml(formatScanDuration(detail.scan_duration)))}
                    ${scanDetailRow('Detection Engine', escapeHtml(displayValue(detail.detection_engine)))}
                    ${scanDetailRow('IP Address', escapeHtml(displayNetworkValue(detail.ip_address, 'ip')))}
                    ${scanDetailRow('Country', escapeHtml(displayNetworkValue(detail.country, 'country')))}
                    ${scanDetailRow('Detection Evidence', scanEvidenceBadges(detail), true)}
                    ${scanDetailRow('Incident Summary', `
                        <div class="scan-detail-subsection">
                            <h4 class="scan-detail-section-title">Threat Behavior</h4>
                            <ul style="margin:0; padding-left:1.1rem;">${behavior.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>
                            <h4 class="scan-detail-section-title" style="margin-top:0.55rem;">Detailed Summary</h4>
                            <pre>${escapeHtml(summary)}</pre>
                        </div>
                    `, true)}
                    ${detailMode === 'safe' ? '' : scanDetailRow(detailMode === 'suspicious' ? 'Cautious Review Actions' : 'NIST Recommended Actions', formatActionList(nistActions), true)}
                    ${detailMode === 'safe' ? '' : scanDetailRow(detailMode === 'suspicious' ? 'Potentially Related MITRE ATT&CK' : 'MITRE ATT&CK Mapping', formatMitreTags(detail.mitre_attack || detail.mitreTags), true)}
                    ${scanDetailRow('User Advisory', `<pre>${escapeHtml(displayValue(detail.user_advisory || detail.userAdvisory))}</pre>`, true)}
                </div>
            `;
            modal.classList.add('show');
            modal.setAttribute('aria-hidden', 'false');
        }

        function closeScanDetailModal() {
            const modal = document.getElementById('scanDetailModal');
            modal.classList.remove('show');
            modal.setAttribute('aria-hidden', 'true');
        }

        async function openScanDetailFromReport(reportId) {
            const response = await fetch(`api/get_report_detail.php?id=${encodeURIComponent(reportId)}`);
            const detail = await parseJsonResponse(response);
            openScanDetailModal(detail);
        }

        function openScanDetailFromSnapshot(snapshotKey) {
            const snap = scanResultSnapshots[snapshotKey];
            if (!snap) return;
            openScanDetailModal({
                username: currentUsername,
                analyzed_at: snap.analyzedTime,
                url: snap.resultUrlText || snap.resultUrlHref,
                status: snap.statusText,
                risk_level: snap.riskText,
                confidence: snap.confidenceText,
                detection_engine: 'ShieldURL ML + LLM Incident Response',
                features: snap.analysisDetails,
                mitreTags: snap.mitreTags,
                llm_summary: snap.incidentSummary,
                nist_response: [...(snap.containmentItems || []), ...(snap.eradicationItems || []), ...(snap.postIncidentItems || [])],
                user_advisory: snap.userAdvisory
            });
        }

        async function viewReportInDashboard(reportId, reportUrl) {
            const resultDiv = document.getElementById('checkResult');
            try {
                const response = await fetch(`api/get_report_detail.php?id=${encodeURIComponent(reportId)}`);
                const detail = await parseJsonResponse(response);
                switchDashboardTab('tab-check-url');

                const status = String(detail.status || 'safe').toLowerCase();
                const confidencePercent = Number(detail.confidence_score || 0) * 100;
                const riskLevel = String(detail.risk_level || mapRiskFromStatus(status));
                const mitre = Array.isArray(detail.mitre_attack) ? detail.mitre_attack : [];
                const detailMode = String(detail.display_status || '').toLowerCase().includes('suspicious') ? 'suspicious' : (status === 'phishing' ? 'phishing' : 'safe');
                const mitrePrimary = detailMode === 'safe' ? 'Not Applicable' : (mitre.length
                    ? `${mitre[0].id || ''}${(mitre[0].id && (mitre[0].name || mitre[0].technique)) ? ' - ' : ''}${mitre[0].name || mitre[0].technique || 'Technique'}`
                    : 'Not Applicable');

                const statusBadge = document.getElementById('statusBadge');
                const detailDisplayStatus = detail.display_status || status;
                const detailDisplayClass = String(detailDisplayStatus).toLowerCase().includes('suspicious') ? 'suspicious' : status;
                statusBadge.className = 'badge ' + detailDisplayClass;
                statusBadge.textContent = String(detailDisplayStatus).toUpperCase();
                document.getElementById('confidenceScore').textContent = confidencePercent.toFixed(2) + '%';
                document.getElementById('confidenceFill').style.width = Math.max(0, Math.min(100, confidencePercent)) + '%';
                document.getElementById('riskLevelValue').textContent = riskLevel.replaceAll('_', ' ').replace(/\b\w/g, c => c.toUpperCase());
                if (document.getElementById('interactionStatusValue')) document.getElementById('interactionStatusValue').textContent = detail.user_interaction_status || 'Not collected';
                updateActionTitles(detail.report_audience);
                updateModelDecisionExplanation({
                    phishing_probability: detail.phishing_probability ?? detail.confidence_score,
                    selected_threshold: detail.selected_threshold,
                    status: detail.status,
                    display_status: detail.display_status,
                    model_policy: detail.model_policy
                });
                updateMitreSummary(detail.report_audience, detailMode, mitrePrimary);
                document.getElementById('resultUrl').href = detail.url || '#';
                document.getElementById('resultUrl').textContent = detail.url || '-';
                document.getElementById('llmSummary').textContent = String(detail.display_status || '').toLowerCase().includes('potentially suspicious')
                    ? 'This URL shows suspicious characteristics, but it is not confirmed phishing. Users should verify the website carefully before entering passwords, OTPs, or sensitive information.'
                    : (detail.llm_summary || 'No incident summary available.');
                document.getElementById('analysisDetails').textContent = JSON.stringify(detail.features || {}, null, 2);
                document.getElementById('analyzedTime').textContent = detail.analyzed_at ? new Date(detail.analyzed_at).toLocaleString() : '-';
                document.getElementById('userAdvisory').textContent = detail.user_advisory || 'No advisory available.';

                renderSimpleListFromSnapshot('containmentList', normalizeToList(detail.incident_response), '');
                renderSimpleListFromSnapshot('eradicationList', normalizeToList(detail.nist_response), '');
                renderSimpleListFromSnapshot('postIncidentList', normalizeToList(detail.post_incident_recommendations), '');

                const mitreContainer = document.getElementById('mitreTags');
                mitreContainer.innerHTML = '';
                (detailMode === 'safe' ? [] : mitre).forEach(item => {
                    const span = document.createElement('span');
                    span.className = 'badge';
                    span.style.background = '#e2e8f0';
                    span.style.color = '#4a5568';
                    span.textContent = `${item.id || ''}${(item.id && (item.name || item.technique)) ? ' - ' : ''}${item.name || item.technique || 'Technique'}`;
                    mitreContainer.appendChild(span);
                });

                const downloadBtn = document.getElementById('downloadReportBtn');
                const downloadLabel = document.getElementById('downloadReportLabel');
                if (reportUrl) {
                    downloadBtn.href = reportUrl;
                    downloadBtn.style.display = 'inline-flex';
                    downloadBtn.classList.remove('is-loading', 'is-success');
                    downloadLabel.textContent = 'Download Report';
                } else {
                    downloadBtn.style.display = 'none';
                }

                const latestScanContext = {
                    checked_url: detail.url || '',
                    detection: {
                        final_verdict: status,
                        display_verdict: detail.display_status || status,
                        confidence_score: Number(detail.confidence_score || 0),
                        phishing_probability: Number(detail.phishing_probability ?? detail.confidence_score ?? 0),
                        selected_threshold: Number(detail.selected_threshold ?? 0.5),
                        model_policy: detail.model_policy || '',
                        risk_level: riskLevel
                    },
                    suspicious_indicators: normalizeToList(detail.incident_response),
                    extracted_features: detail.features || {},
                    mitre_attack: mitre,
                    nist_actions: {
                        containment: normalizeToList(detail.incident_response),
                        eradication_recovery: normalizeToList(detail.nist_response),
                        post_incident: normalizeToList(detail.post_incident_recommendations)
                    },
                    user_advisory: detail.user_advisory || ''
                };

                currentScanId = reportId;
                resetAssistant(reportId, latestScanContext);
                document.getElementById('analysisResult').classList.add('show');
                const technicalPanel = document.getElementById('technicalDetailsPanel');
                if (technicalPanel) {
                    technicalPanel.open = getPreference('shieldurl_pref_technical', 'collapsed') === 'expanded';
                }
                hasScanResult = true;
                isScanRunning = false;
                setScanInteractionState({
                    inputDisabled: true,
                    buttonDisabled: false,
                    buttonLabel: 'Recheck URL'
                });
                resultDiv.className = 'result-message success';
                resultDiv.textContent = 'Loaded saved scan result.';
            } catch (error) {
                resultDiv.className = 'result-message error';
                resultDiv.textContent = error.message || 'Unable to load saved scan result.';
            }
        }

        function setAssistantPanelOpen(isOpen) {
            const assistantColumn = document.getElementById('assistantColumn');
            const assistantOverlay = document.getElementById('assistantOverlay');
            const toggleBtn = document.getElementById('assistantToggleBtn');
            const toggleLabel = document.getElementById('assistantToggleLabel');
            assistantPanelOpen = Boolean(isOpen);
            if (assistantColumn) {
                assistantColumn.classList.toggle('assistant-open', assistantPanelOpen);
            }
            if (assistantOverlay) {
                assistantOverlay.setAttribute('aria-hidden', assistantPanelOpen ? 'false' : 'true');
            }
            if (toggleBtn) {
                toggleBtn.style.display = assistantPanelOpen ? 'none' : 'inline-flex';
            }
            if (toggleLabel) {
                toggleLabel.textContent = 'Open ShieldURL Assistant';
            }
            if (assistantPanelOpen) {
                setTimeout(() => document.querySelector('.assistant-category-btn:not(:disabled)')?.focus(), 180);
            }
        }

        function mountAssistantToViewport() {
            const assistantColumn = document.getElementById('assistantColumn');
            const toggleBtn = document.getElementById('assistantToggleBtn');
            if (assistantColumn && assistantColumn.parentElement !== document.body) {
                document.body.appendChild(assistantColumn);
            }
            if (toggleBtn && toggleBtn.parentElement !== document.body) {
                document.body.appendChild(toggleBtn);
            }
        }

        function updateAssistantToggleAvailability(hasScanContext) {
            const toggleBtn = document.getElementById('assistantToggleBtn');
            const toggleLabel = document.getElementById('assistantToggleLabel');
            if (!toggleBtn) {
                return;
            }
            if (hasScanContext) {
                toggleBtn.style.display = assistantPanelOpen ? 'none' : 'inline-flex';
                toggleBtn.disabled = false;
                if (toggleLabel) {
                    toggleLabel.textContent = 'Open ShieldURL Assistant';
                }
            } else {
                toggleBtn.style.display = assistantPanelOpen ? 'none' : 'inline-flex';
                toggleBtn.disabled = false;
                if (toggleLabel) {
                    toggleLabel.textContent = 'Open ShieldURL Assistant';
                }
            }
            setAssistantPanelOpen(false);
        }

        function appendAssistantMessage(role, text) {
            const messages = document.getElementById('assistantMessages');
            if (!messages) {
                return null;
            }
            const emptyNotice = messages.querySelector('.assistant-message.notice');
            if (emptyNotice) {
                emptyNotice.remove();
            }
            const bubble = document.createElement('div');
            bubble.className = 'assistant-message ' + role;
            if (role === 'assistant') {
                renderAssistantAnswer(bubble, text);
            } else {
                bubble.textContent = text;
            }
            bubble.classList.add('message-enter');
            messages.appendChild(bubble);
            messages.scrollTop = messages.scrollHeight;
            return bubble;
        }

        function renderAssistantAnswer(container, text) {
            container.textContent = '';
            const raw = String(text || '').trim();
            if (!raw) {
                return;
            }

            const sections = raw.split(/\n{2,}/).map(part => part.trim()).filter(Boolean);
            if (!sections.length) {
                container.textContent = raw;
                return;
            }

            sections.forEach(section => {
                const block = document.createElement('div');
                block.className = 'assistant-answer-section';
                const lines = section.split(/\n/).map(line => line.trim()).filter(Boolean);
                const firstLine = lines[0] || '';
                const labelMatch = firstLine.match(/^([^:]{2,40}):\s*(.*)$/);

                if (labelMatch) {
                    const label = document.createElement('strong');
                    label.className = 'assistant-answer-label';
                    label.textContent = labelMatch[1] + ':';
                    block.appendChild(label);

                    const body = document.createElement('div');
                    body.className = 'assistant-answer-text';
                    body.textContent = [labelMatch[2], ...lines.slice(1)].filter(Boolean).join(' ');
                    block.appendChild(body);
                } else {
                    const body = document.createElement('div');
                    body.className = 'assistant-answer-text';
                    body.textContent = lines.join(' ');
                    block.appendChild(body);
                }

                container.appendChild(block);
            });
        }

        function getAssistantConversation() {
            return Array.from(document.querySelectorAll('#assistantMessages .assistant-message'))
                .filter(item => !item.classList.contains('notice'))
                .slice(-6)
                .map(item => ({
                    role: item.classList.contains('user') ? 'user' : 'assistant',
                    content: item.textContent || ''
                }));
        }

        const assistantQuestionSets = {
            'Scan Analysis Details': [
                'What does this result mean?',
                'Why was this URL flagged?',
                'What is the confidence score?',
                'What indicators were detected?',
                'Is this URL dangerous?',
                'Why is this URL considered safe?'
            ],
            'MITRE ATT&CK': [
                'What does this MITRE tag mean?',
                'What is T1566.002?',
                'How is this related to phishing?',
                'Why was this attack technique selected?',
                'Is this credential theft?',
                'What attack behavior was detected?'
            ],
            'Recommended Response': [
                'What should I do now?',
                'Should I block this URL?',
                'Should I reset my password?',
                'Should I report this incident?',
                'What should the IT team do?',
                'Is device isolation necessary?'
            ],
            'Risk & Severity': [
                'How severe is this threat?',
                'What does high risk mean?',
                'Can this affect the organization?',
                'Is this likely a false positive?',
                'What happens if users click this URL?'
            ],
            'User Safety Advice': [
                'What should I avoid doing?',
                'Is it safe to open this link?',
                'Can this steal credentials?',
                'Can this install malware?',
                'What should I tell employees?'
            ],
            'ShieldURL Help': [
                'What is ShieldURL?',
                'How does ShieldURL work?',
                'What is lexical detection model?',
                'How accurate is the detection?',
                'What is phishing?'
            ]
        };
        let assistantActiveCategory = 'Scan Analysis Details';

        function renderAssistantCategories() {
            const categoryBar = document.getElementById('assistantCategoryBar');
            if (!categoryBar) return;
            categoryBar.innerHTML = '';
            Object.keys(assistantQuestionSets).forEach(category => {
                const button = document.createElement('button');
                button.type = 'button';
                button.className = 'assistant-category-btn' + (category === assistantActiveCategory ? ' active' : '');
                button.textContent = category;
                button.dataset.assistantCategory = category;
                categoryBar.appendChild(button);
            });
        }

        function getAssistantScanMode() {
            const context = currentScanContext || {};
            const detection = context.detection && typeof context.detection === 'object' ? context.detection : {};
            const text = [
                detection.display_verdict,
                detection.final_verdict,
                detection.risk_level,
                context.display_verdict,
                context.final_verdict,
                context.risk_level
            ].filter(Boolean).join(' ').toLowerCase();

            if (text.includes('potentially suspicious') || text.includes('suspicious')) {
                return 'suspicious';
            }
            if (text.includes('phishing') || text.includes('high')) {
                return 'phishing';
            }
            if (text.includes('safe') || text.includes('legitimate') || text.includes('low')) {
                return 'safe';
            }
            return 'unknown';
        }

        function getVisibleAssistantQuestions(category) {
            const questions = assistantQuestionSets[category] || [];
            const mode = getAssistantScanMode();
            return questions.filter(question => {
                if (question === 'Why is this URL considered safe?') {
                    return mode === 'safe';
                }
                return true;
            });
        }

        function renderAssistantQuestions(category = assistantActiveCategory) {
            assistantActiveCategory = assistantQuestionSets[category] ? category : 'Scan Analysis Details';
            const title = document.getElementById('assistantQuestionTitle');
            const list = document.getElementById('assistantQuestionList');
            if (title) {
                title.textContent = assistantActiveCategory;
            }
            if (!list) return;
            list.innerHTML = '';
            getVisibleAssistantQuestions(assistantActiveCategory).forEach(question => {
                const button = document.createElement('button');
                button.type = 'button';
                button.className = 'assistant-question-btn';
                button.textContent = question;
                button.dataset.assistantQuestion = question;
                list.appendChild(button);
            });
            renderAssistantCategories();
            setAssistantEnabled(Boolean(currentScanContext));
        }

        function setAssistantEnabled(enabled) {
            const buttons = document.querySelectorAll('.assistant-question-btn, .assistant-category-btn');
            buttons.forEach(button => {
                button.disabled = !enabled || assistantIsLoading;
            });
        }

        function resetAssistant(scanId, scanContext) {
            currentScanId = scanId || null;
            currentScanContext = scanContext || null;
            const hasContext = Boolean(currentScanContext);
            const messages = document.getElementById('assistantMessages');
            if (messages) {
                messages.innerHTML = '';
                appendAssistantMessage('assistant', 'Welcome. Choose a category, then select a question about this scan result.');
                if (!hasContext) {
                    appendAssistantMessage('notice', 'Please scan a URL first before using the assistant.');
                }
            }
            assistantActiveCategory = 'Scan Analysis Details';
            renderAssistantQuestions(assistantActiveCategory);
            setAssistantEnabled(hasContext);
            updateAssistantToggleAvailability(hasContext);
        }

        async function sendAssistantQuestion(question) {
            const trimmed = String(question || '').trim();
            if (!currentScanContext) {
                appendAssistantMessage('notice', 'Please scan a URL first before using the assistant.');
                setAssistantEnabled(false);
                return;
            }
            if (!trimmed) {
                return;
            }
            if (trimmed.length > 500) {
                appendAssistantMessage('assistant', 'Please keep questions to 500 characters or fewer.');
                return;
            }

            appendAssistantMessage('user', trimmed);
            assistantIsLoading = true;
            setAssistantEnabled(true);
            const loadingBubble = appendAssistantMessage('assistant', 'ShieldURL Assistant is analyzing...');

            try {
                const conversation = getAssistantConversation();
                const response = await fetch('api/chat.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        scan_id: currentScanId,
                        message: trimmed,
                        assistant_response_style: 'simple',
                        scan_context: currentScanContext,
                        history: conversation,
                        conversation,
                    }),
                });
                const result = await parseJsonResponse(response);
                renderAssistantAnswer(loadingBubble, result.answer || 'Status:\nThe assistant is temporarily unavailable, but the scan result remains valid.\n\nRecommended action:\nPlease follow the displayed recommended actions.');
            } catch (error) {
                renderAssistantAnswer(loadingBubble, 'Status:\nThe assistant is temporarily unavailable, but the scan result remains valid.\n\nRecommended action:\nPlease follow the displayed recommended actions.');
            } finally {
                assistantIsLoading = false;
                setAssistantEnabled(Boolean(currentScanContext));
            }
        }

        document.getElementById('assistantCategoryBar')?.addEventListener('click', (event) => {
            const button = event.target.closest('[data-assistant-category]');
            if (!button || button.disabled) return;
            renderAssistantQuestions(button.dataset.assistantCategory);
        });

        document.getElementById('assistantQuestionList')?.addEventListener('click', (event) => {
            const button = event.target.closest('[data-assistant-question]');
            if (!button || button.disabled) return;
            sendAssistantQuestion(button.dataset.assistantQuestion);
        });

        const assistantToggleBtn = document.getElementById('assistantToggleBtn');
        if (assistantToggleBtn) {
            assistantToggleBtn.addEventListener('click', () => {
                setAssistantPanelOpen(!assistantPanelOpen);
            });
        }
        document.getElementById('assistantCloseBtn')?.addEventListener('click', () => setAssistantPanelOpen(false));
        document.getElementById('assistantOverlay')?.addEventListener('click', () => setAssistantPanelOpen(false));
        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape' && assistantPanelOpen) {
                setAssistantPanelOpen(false);
            }
        });

        mountAssistantToViewport();

        resetAssistant(null);

        // Check URL
        document.getElementById('checkUrlForm').addEventListener('submit', async (e) => {
            e.preventDefault();

            if (isScanRunning) {
                return;
            }

            if (hasScanResult) {
                resetScanViewForRecheck();
                return;
            }

            const url = document.getElementById('url').value;
            const clicked = await askClickedStatus();
            const resultDiv = document.getElementById('checkResult');
            const body = document.body;
            const shieldLabel = document.getElementById('shieldLabel');
            const shieldTitle = document.getElementById('shieldTitle');
            const shieldSubtitle = document.getElementById('shieldSubtitle');

            const setLoadingMessage = (message) => {
                resultDiv.className = 'result-message loading';
                resultDiv.innerHTML = `<span class="loading-spinner" aria-hidden="true"></span><span>${message}</span>`;
            };

            let loadingTimer1 = null;
            let loadingTimer2 = null;
            const clearLoadingTimers = () => {
                if (loadingTimer1) {
                    clearTimeout(loadingTimer1);
                    loadingTimer1 = null;
                }
                if (loadingTimer2) {
                    clearTimeout(loadingTimer2);
                    loadingTimer2 = null;
                }
            };

            setLoadingMessage('Analyzing URL detection...');
            isScanRunning = true;
            resetAssistant(null);
            setScanInteractionState({
                inputDisabled: true,
                buttonDisabled: true,
                buttonLabel: 'Scanning...'
            });
            body.classList.remove('status-safe', 'status-warn', 'status-danger');
            body.classList.add('status-scanning');
            shieldLabel.textContent = 'SCAN';
            shieldTitle.textContent = 'Scanning signals';
            shieldSubtitle.textContent = 'Shield is sweeping for phishing patterns.';

            loadingTimer1 = setTimeout(() => {
                setLoadingMessage('Generating AI incident response report...');
            }, 2000);
            loadingTimer2 = setTimeout(() => {
                setLoadingMessage('Ollama is preparing the NIST-aligned report. This may take a moment.');
            }, 6000);

            try {
                const response = await fetch('api/analyze.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ url, clicked })
                });

                const result = await parseJsonResponse(response);
                console.log('API result:', result);
                console.log('result.llm_report:', result.llm_report);
                console.log('result.llm:', result.llm);
                console.log('result.timing:', result.timing);
                console.log('result.debug:', result.debug);

                const detection = result.detection && typeof result.detection === 'object' ? result.detection : {};
                const hasDetection = Object.keys(detection).length > 0;
                const hasOverall = result.overall && typeof result.overall === 'object' && Object.keys(result.overall).length > 0;
                const hasMl = result.ml && typeof result.ml === 'object' && Object.keys(result.ml).length > 0;
                const isSuccessfulScan = result.success === true || hasDetection || hasOverall || hasMl;

                if (isSuccessfulScan) {
                    clearLoadingTimers();
                    resultDiv.className = 'result-message success';
                    const llmReport = result.llm_report && typeof result.llm_report === 'object' ? result.llm_report : {};
                    const llmBridge = result.llm && typeof result.llm === 'object' ? result.llm : {};
                    const llmResponse = result.llm_response && typeof result.llm_response === 'object' ? result.llm_response : {};
                    const llm = Object.keys(llmReport).length ? llmReport : (Object.keys(llmBridge).length ? llmBridge : llmResponse);
                    const aiUnavailable = (llm && llm.error) ? ' AI report unavailable or fallback used; detection result is still valid.' : '';
                    const modelPolicy = simplePolicyText(result.model_policy || result.overall?.model_policy || result.ml?.model_policy);
                    resultDiv.textContent = 'Analysis completed. ' + modelPolicy + aiUnavailable;

                    // Update result display
                    const displayUrl = result.url || detection.url || url;
                    document.getElementById('resultUrl').href = displayUrl;
                    document.getElementById('resultUrl').textContent = displayUrl;

                    const rawConfidence = Number(result.phishing_probability ?? result.confidence_score ?? detection.phishing_probability ?? detection.confidence_score ?? 0);
                    const confidence = rawConfidence <= 1 ? rawConfidence * 100 : rawConfidence;
                    document.getElementById('confidenceScore').textContent = confidence.toFixed(2) + '%';
                    document.getElementById('confidenceFill').style.width = confidence + '%';
                    updateModelDecisionExplanation(result);
                    const displayRisk = String(result.risk_level || detection.risk_level || result.overall?.risk_level || 'unknown')
                        .replaceAll('_', ' ')
                        .replace(/\b\w/g, (c) => c.toUpperCase());
                    document.getElementById('riskLevelValue').textContent = displayRisk;
                    if (document.getElementById('interactionStatusValue')) document.getElementById('interactionStatusValue').textContent = result.user_interaction_status || result.llm_report?.user_interaction_status || 'Not collected';
                    updateActionTitles(result.report_audience || result.llm_report?.audience);

                    const features = result.features || detection.features || {};
                    document.getElementById('analysisDetails').textContent = JSON.stringify(features, null, 2); // Show features for now as "details"
                    document.getElementById('analyzedTime').textContent = new Date().toLocaleString();

                    const pickFirst = (...values) => {
                        for (const value of values) {
                            if (Array.isArray(value) && value.length > 0) {
                                return value;
                            }
                            if (typeof value === 'string' && value.trim() !== '') {
                                return value;
                            }
                            if (value && typeof value === 'object' && !Array.isArray(value)) {
                                return value;
                            }
                        }
                        return null;
                    };
                    const normalizeList = (value) => {
                        if (Array.isArray(value)) {
                            return value.filter(item => item !== null && item !== undefined && String(item).trim() !== '');
                        }
                        if (typeof value === 'string') {
                            const trimmed = value.trim();
                            if (!trimmed) {
                                return [];
                            }
                            try {
                                const parsed = JSON.parse(trimmed);
                                return Array.isArray(parsed) ? parsed : [trimmed];
                            } catch (error) {
                                return [trimmed];
                            }
                        }
                        return [];
                    };
                    const renderGroupedList = (container, groups, emptyMessage) => {
                        container.innerHTML = '';
                        const filledGroups = groups.filter(group => group.items.length > 0);
                        if (!filledGroups.length) {
                            return;
                        }
                        filledGroups.forEach(group => {
                            const groupHeader = document.createElement('li');
                            groupHeader.style.marginBottom = '0.75rem';
                            groupHeader.innerHTML = `<strong>${group.title}</strong>`;

                            const sublist = document.createElement('ul');
                            sublist.style.paddingLeft = '1rem';
                            sublist.style.margin = '0.35rem 0 0';
                            group.items.forEach(item => {
                                const subitem = document.createElement('li');
                                subitem.textContent = typeof item === 'string' ? item : JSON.stringify(item);
                                sublist.appendChild(subitem);
                            });
                            groupHeader.appendChild(sublist);
                            container.appendChild(groupHeader);
                        });
                    };
                    const renderSimpleList = (container, items, emptyMessage) => {
                        if (!container) return;
                        const card = container.closest('.action-card');
                        container.innerHTML = '';
                        items = dedupeRenderItems(items || []);
                        if (!items.length) {
                            if (card) card.style.display = 'none';
                            return;
                        }
                        if (card) card.style.display = '';
                        items.forEach(item => {
                            const li = document.createElement('li');
                            li.textContent = typeof item === 'string' ? item : JSON.stringify(item);
                            container.appendChild(li);
                        });
                    };
                    const dedupeTextItems = (items) => {
                        const seen = new Set();
                        return items.filter(item => {
                            const key = (typeof item === 'string' ? item : JSON.stringify(item)).trim().toLowerCase();
                            if (!key || seen.has(key)) return false;
                            seen.add(key);
                            return true;
                        });
                    };
                    const collectList = (...values) => dedupeTextItems(values.flatMap(value => normalizeList(value)));
                    const formatMitreTag = (tech) => {
                        if (typeof tech === 'string') {
                            return tech;
                        }
                        if (!tech || typeof tech !== 'object') {
                            return JSON.stringify(tech);
                        }
                        const techId = tech.id || tech.technique_id || tech.tactic_id || '';
                        const techName = tech.name || tech.technique || tech.tactic || '';
                        const rationale = tech.rationale || tech.reason || tech.description || '';
                        const base = [techId, techName].filter(Boolean).join(' - ');
                        if (base && rationale) {
                            return `${base} - ${rationale}`;
                        }
                        return base || rationale || JSON.stringify(tech);
                    };
                    const dedupeMitreTags = (items) => {
                        const seen = new Set();
                        return items.filter(item => {
                            let key = '';
                            if (item && typeof item === 'object' && !Array.isArray(item)) {
                                const techId = item.id || item.technique_id || item.tactic_id || '';
                                const techName = item.name || item.technique || item.tactic || '';
                                key = `${String(techId).toLowerCase()}|${String(techName).toLowerCase()}`;
                            } else {
                                key = String(item).trim().toLowerCase();
                            }
                            if (!key || seen.has(key)) {
                                return false;
                            }
                            seen.add(key);
                            return true;
                        });
                    };
                    const fallbackIncidentSummary = () => {
                        const verdict = String(result.display_status || result.overall?.display_verdict || result.overall?.verdict || result.overall?.status || detection.display_verdict || detection.final_verdict || 'unknown').replaceAll('_', ' ').toLowerCase();
                        const risk = String(result.overall?.risk_level || detection.risk_level || 'unknown').toLowerCase();
                        if (verdict.includes('potentially suspicious')) {
                            return 'This URL shows suspicious characteristics, but it is not confirmed phishing. Users should verify the website carefully before entering passwords, OTPs, or sensitive information.';
                        }
                        return `The submitted URL was classified as ${verdict} with ${risk} risk based on the supplied scan context. ${verdictPolicyText(verdict)}`;
                    };
                    const fallbackUserAdvisory = 'Review the URL carefully before interacting with it. Verify the destination before entering login details, OTP, banking information, or personal data.';

                    const potentiallySuspiciousDisplay = String(result.display_status || result.overall?.display_verdict || detection.display_verdict || '').toLowerCase().includes('potentially suspicious');
                    const verdictMode = potentiallySuspiciousDisplay ? 'suspicious' : (String(result.status || detection.final_verdict || '').toLowerCase() === 'phishing' ? 'phishing' : 'safe');
                    const incidentSummary = potentiallySuspiciousDisplay
                        ? 'This URL shows suspicious characteristics, but it is not confirmed phishing. Users should verify the website carefully before entering passwords, OTPs, or sensitive information.'
                        : (pickFirst(
                        llm.incident_summary,
                        llm.executive_summary,
                        result.llm_summary
                    ) || fallbackIncidentSummary());
                    document.getElementById('llmSummary').textContent = incidentSummary;

                    const containmentActions = collectList(
                        llm.containment_actions,
                        result.containment_actions
                    );
                    const eradicationActions = collectList(
                        llm.eradication_recovery_actions,
                        result.eradication_recovery_actions
                    );
                    const postIncidentActions = collectList(
                        llm.post_incident_recommendations,
                        result.post_incident_recommendations
                    );
                    const fallbackNist = collectList(
                        llm.nist_response,
                        result.nist_response
                    );
                    const fallbackIncident = collectList(
                        llm.incident_response,
                        result.incident_response
                    );

                    const hasPrimaryActions = containmentActions.length || eradicationActions.length || postIncidentActions.length;
                    const recommendedActions = [...new Set([
                        ...containmentActions,
                        ...eradicationActions,
                        ...postIncidentActions,
                        ...(hasPrimaryActions ? [] : fallbackIncident)
                    ])];
                    const nistGroups = [
                        { title: 'Containment', items: containmentActions.length ? containmentActions : (hasPrimaryActions ? [] : fallbackNist) },
                        { title: 'Eradication & Recovery', items: eradicationActions.length ? eradicationActions : (hasPrimaryActions ? [] : fallbackNist) },
                        { title: 'Post-Incident Recommendations', items: postIncidentActions.length ? postIncidentActions : (hasPrimaryActions ? [] : fallbackNist) }
                    ];

                    const irContainer = document.getElementById('irSteps');
                    const nistContainer = document.getElementById('nistSteps');
                    const nistField = document.getElementById('nistResponseField');
                    renderGroupedList(irContainer, [
                        { title: 'Containment', items: containmentActions },
                        { title: 'Eradication & Recovery', items: eradicationActions },
                        { title: 'Post-Incident Recommendations', items: postIncidentActions },
                        ...(hasPrimaryActions ? [] : [{ title: 'Incident Response', items: fallbackIncident }])
                    ], '');
                    const shouldShowNist = !hasPrimaryActions && fallbackNist.length > 0;
                    if (shouldShowNist) {
                        renderGroupedList(nistContainer, nistGroups, '');
                        nistField.style.display = '';
                    } else {
                        nistContainer.innerHTML = '';
                        nistField.style.display = 'none';
                    }

                    const userAdvisory = pickFirst(
                        llm.user_advisory,
                        result.user_advisory
                    ) || fallbackUserAdvisory;
                    document.getElementById('userAdvisory').textContent = userAdvisory;
                    renderSimpleList(document.getElementById('containmentList'), containmentActions, '');
                    renderSimpleList(document.getElementById('eradicationList'), eradicationActions, '');
                    renderSimpleList(document.getElementById('postIncidentList'), postIncidentActions, '');

                    const mitreContainer = document.getElementById('mitreTags');
                    mitreContainer.innerHTML = '';
                    const mitreMapping = verdictMode === 'safe' ? [] : dedupeMitreTags(
                        collectList(
                            llm.mitre_attack_mapping,
                            result.mitre_attack_mapping,
                            llm.mitre_techniques,
                            result.mitre_techniques
                        )
                    );
                    if (mitreMapping.length) {
                        mitreMapping.forEach(tech => {
                            const span = document.createElement('span');
                            span.className = 'badge';
                            span.style.background = '#e2e8f0';
                            span.style.color = '#4a5568';
                            span.style.marginRight = '5px';
                            span.textContent = formatMitreTag(tech);
                            mitreContainer.appendChild(span);
                        });
                    }
                    updateMitreSummary(result.report_audience || result.llm_report?.audience, verdictMode, verdictMode === 'safe' ? 'Not Applicable' : (mitreMapping.length ? formatMitreTag(mitreMapping[0]) : 'Not Applicable'));

                    // Set Report Link (We assume we can get the ID from result or just reload history... 
                    // Wait, result usually doesn't return the NEW ID unless we add it to analyze.php output.
                    // Let's assume the user will see it in history or we add ID to output.
                    // For now, let's auto-refresh history and get the latest ID? 
                    // No, better to update analyze.php to return `id`.
                    // But I didn't update analyze.php to return lastInsertId.
                    // I should fix that.
                    // For now, I'll cheat: The user can click "Refresh" or I'll reload the page? No.
                    // I will update analyze.php to return the ID.

                    // IF I forget, the report link won't work immediately.
                    // Let's assume analyze.php returns `report_id` if I add it.
                    // I will add it in next step or use fallback.
                    const latestScanContext = {
                        checked_url: displayUrl,
                        detection: {
                            final_verdict: result.status || detection.final_verdict || result.overall?.status || 'unknown',
                            display_verdict: result.display_status || result.overall?.display_verdict || detection.display_verdict || '',
                            confidence_score: Number(result.phishing_probability ?? result.confidence_score ?? detection.phishing_probability ?? detection.confidence_score ?? 0),
                            phishing_probability: Number(result.phishing_probability ?? detection.phishing_probability ?? 0),
                            selected_threshold: Number(result.selected_threshold ?? result.ml?.selected_threshold ?? detection.lexical_threshold ?? 0.5),
                            model_policy: result.model_policy || result.overall?.model_policy || result.ml?.model_policy || '',
                            risk_level: result.risk_level || detection.risk_level || result.overall?.risk_level || 'unknown'
                        },
                        suspicious_indicators: collectList(
                            result.heuristics?.reasons,
                            detection.heuristic_reasons,
                            detection.suspicious_indicators
                        ),
                        extracted_features: features,
                        mitre_attack: mitreMapping,
                        nist_actions: {
                            containment: containmentActions,
                            eradication_recovery: eradicationActions,
                            post_incident: postIncidentActions
                        },
                        user_advisory: userAdvisory
                    };

                    if (result.report_id) {
                        const downloadBtn = document.getElementById('downloadReportBtn');
                        const downloadLabel = document.getElementById('downloadReportLabel');
                        downloadBtn.href = 'api/download_report.php?id=' + result.report_id;
                        downloadBtn.style.display = 'inline-flex';
                        downloadBtn.classList.remove('is-loading', 'is-success');
                        downloadLabel.textContent = 'Download Report';
                    } else {
                        document.getElementById('downloadReportBtn').style.display = 'none';
                    }
                    const displayStatus = result.status || detection.final_verdict || 'safe';
                    const displayStatusText = result.display_status || result.overall?.display_verdict || detection.display_verdict || displayStatus;
                    const displayStatusNormalized = String(displayStatusText).toLowerCase();
                    const displayStatusClass = displayStatusNormalized.includes('suspicious') ? 'suspicious' : String(displayStatus).toLowerCase();
                    const statusBadge = document.getElementById('statusBadge');
                    statusBadge.className = 'badge ' + displayStatusClass;
                    statusBadge.textContent = String(displayStatusText).toUpperCase();
                    resetAssistant(result.report_id, latestScanContext);
                    const reportUrl = result.report_id ? `api/download_report.php?id=${result.report_id}` : '';
                    const snapshotKey = captureCurrentResultSnapshot(reportUrl);
                    const saveHistoryPref = getPreference('shieldurl_pref_save_history', 'enabled');
                    if (saveHistoryPref === 'enabled') {
                        localScanHistory.unshift({
                            key: snapshotKey,
                            analyzedAt: new Date().toISOString(),
                            url: displayUrl,
                            status: displayStatusText,
                            machineStatus: displayStatus,
                            confidence: confidence,
                            riskLevel: displayRisk,
                            reportUrl
                        });
                    }

                    if (result.llm_pending && result.report_id) {
                        document.getElementById('llmSummary').textContent = 'AI report is being prepared. The URL safety result is already available.';
                        fetch('api/generate_report.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ report_id: result.report_id })
                        })
                            .then(parseJsonResponse)
                            .then((reportResult) => {
                                const generated = reportResult.llm_report && typeof reportResult.llm_report === 'object' ? reportResult.llm_report : {};
                                if (!reportResult.success || !Object.keys(generated).length) return;
                                const stillPotentiallySuspicious = String(displayStatusText).toLowerCase().includes('potentially suspicious');
                                document.getElementById('llmSummary').textContent = stillPotentiallySuspicious
                                    ? 'This URL shows suspicious characteristics, but it is not confirmed phishing. Users should verify the website carefully before entering passwords, OTPs, or sensitive information.'
                                    : (generated.incident_summary || 'AI report is ready.');
                                const generatedContainment = collectList(generated.containment_actions);
                                const generatedEradication = collectList(generated.eradication_recovery_actions);
                                const generatedPost = collectList(generated.post_incident_recommendations);
                                renderSimpleList(document.getElementById('containmentList'), generatedContainment, '');
                                renderSimpleList(document.getElementById('eradicationList'), generatedEradication, '');
                                renderSimpleList(document.getElementById('postIncidentList'), generatedPost, '');
                                document.getElementById('userAdvisory').textContent = generated.user_advisory || document.getElementById('userAdvisory').textContent;
                                const generatedMitre = verdictMode === 'safe' ? [] : dedupeMitreTags(collectList(generated.mitre_attack_mapping));
                                mitreContainer.innerHTML = '';
                                generatedMitre.forEach(tech => {
                                    const span = document.createElement('span');
                                    span.className = 'badge';
                                    span.style.background = '#e2e8f0';
                                    span.style.color = '#4a5568';
                                    span.style.marginRight = '5px';
                                    span.textContent = formatMitreTag(tech);
                                    mitreContainer.appendChild(span);
                                });
                                updateMitreSummary(reportResult.report_audience || generated.audience, verdictMode, verdictMode === 'safe' ? 'Not Applicable' : (generatedMitre.length ? formatMitreTag(generatedMitre[0]) : 'Not Applicable'));
                                loadHistory();
                            })
                            .catch((error) => console.warn('AI report generation failed:', error));
                    }

                    document.getElementById('analysisResult').classList.add('show');
                    const technicalPanel = document.getElementById('technicalDetailsPanel');
                    if (technicalPanel) {
                        technicalPanel.open = getPreference('shieldurl_pref_technical', 'collapsed') === 'expanded';
                    }
                    hasScanResult = true;
                    isScanRunning = false;
                    setScanInteractionState({
                        inputDisabled: true,
                        buttonDisabled: false,
                        buttonLabel: 'Recheck URL'
                    });

                    body.classList.remove('status-scanning');
                    let mode = 'safe';
                    if (displayStatusNormalized.includes('suspicious')) {
                        mode = 'warn';
                    } else if (displayStatus === 'phishing') {
                        mode = 'danger';
                    } else if (displayStatus === 'suspicious') {
                        mode = 'warn';
                    }
                    body.classList.remove('status-safe', 'status-warn', 'status-danger');
                    body.classList.add('status-' + mode);
                    const labelMap = { safe: 'SAFE', warn: 'WARN', danger: 'BLOCK' };
                    const titleMap = {
                        safe: 'Shield locked: safe',
                        warn: 'Review carefully',
                        danger: 'Shield blocking threats'
                    };
                    const subtitleMap = {
                        safe: 'Protection is stable and the URL looks clean.',
                        warn: 'Suspicious signals detected, but this URL is not confirmed as phishing. Review the URL carefully before interacting with it.',
                        danger: 'High-risk signals detected. Avoid this link.'
                    };
                    shieldLabel.textContent = labelMap[mode];
                    shieldTitle.textContent = titleMap[mode];
                    shieldSubtitle.textContent = subtitleMap[mode];
                    const shieldVisual = document.querySelector('.shield-visual');
                    if (shieldVisual) {
                        shieldVisual.classList.remove('bursting');
                        void shieldVisual.offsetWidth;
                        shieldVisual.classList.add('bursting');
                        setTimeout(() => {
                            shieldVisual.classList.remove('bursting');
                        }, 900);
                    }

                    // Reload history
                    setTimeout(() => loadHistory(), 500);
                } else {
                    clearLoadingTimers();
                    isScanRunning = false;
                    setScanInteractionState({
                        inputDisabled: false,
                        buttonDisabled: false,
                        buttonLabel: 'Scan URL'
                    });
                    resultDiv.className = 'result-message error';
                    resultDiv.textContent = result.message || 'Analysis failed. Please try again.';
                }
            } catch (error) {
                clearLoadingTimers();
                isScanRunning = false;
                setScanInteractionState({
                    inputDisabled: false,
                    buttonDisabled: false,
                    buttonLabel: 'Scan URL'
                });
                console.error('Scan request failed:', error);
                resultDiv.className = 'result-message error';
                resultDiv.textContent = error.message || 'Analysis failed. Please try again.';
                document.body.classList.remove('status-scanning');
            }
        });

        // Load History
        function getDomainFromUrl(url) {
            try {
                return new URL(String(url || '').startsWith('http') ? url : 'http://' + url).hostname.toLowerCase();
            } catch (error) {
                return '';
            }
        }

        function getFilteredHistoryRows() {
            const search = document.getElementById('historySearch').value.trim().toLowerCase();
            const status = document.getElementById('historyFilter').value;
            const sort = document.getElementById('historySort').value;
            const fromDate = document.getElementById('historyDateFrom').value;
            const toDate = document.getElementById('historyDateTo').value;
            const fromTime = fromDate ? new Date(fromDate + 'T00:00:00').getTime() : null;
            const toTime = toDate ? new Date(toDate + 'T23:59:59').getTime() : null;

            return historyRowsCache
                .filter(row => {
                    const rowStatus = String(row.machineStatus || row.status || '').toLowerCase();
                    const rowDisplayStatus = String(row.status || '').toLowerCase();
                    if (status && rowStatus !== status.toLowerCase() && rowDisplayStatus !== status.toLowerCase()) return false;

                    const analyzedTime = new Date(row.analyzedAt).getTime();
                    if (fromTime && analyzedTime < fromTime) return false;
                    if (toTime && analyzedTime > toTime) return false;

                    if (search) {
                        const url = String(row.url || '').toLowerCase();
                        const domain = getDomainFromUrl(row.url);
                        if (!url.includes(search) && !domain.includes(search)) return false;
                    }
                    return true;
                })
                .sort((a, b) => {
                    const aTime = new Date(a.analyzedAt).getTime() || 0;
                    const bTime = new Date(b.analyzedAt).getTime() || 0;
                    return sort === 'oldest' ? aTime - bTime : bTime - aTime;
                });
        }

        function renderHistoryPagination(totalRows, totalPages, startIndex, endIndex) {
            const info = document.getElementById('historyPageInfo');
            const controls = document.getElementById('historyPageControls');
            if (totalRows === 0) {
                info.textContent = 'Showing 0 of 0 scans';
                controls.innerHTML = '';
                return;
            }

            info.textContent = `Showing ${startIndex + 1}-${endIndex} of ${totalRows} scans`;
            let html = `<button class="page-btn" data-history-page="${historyCurrentPage - 1}" ${historyCurrentPage === 1 ? 'disabled' : ''}>Previous</button>`;
            for (let page = 1; page <= totalPages; page++) {
                html += `<button class="page-btn ${page === historyCurrentPage ? 'active' : ''}" data-history-page="${page}">${page}</button>`;
            }
            html += `<button class="page-btn" data-history-page="${historyCurrentPage + 1}" ${historyCurrentPage === totalPages ? 'disabled' : ''}>Next</button>`;
            controls.innerHTML = html;
        }

        function renderHistoryTable() {
            const tbody = document.getElementById('historyTableBody');
            const rows = getFilteredHistoryRows();
            const totalRows = rows.length;
            const totalPages = Math.max(1, Math.ceil(totalRows / historyPageSize));
            historyCurrentPage = Math.min(Math.max(1, historyCurrentPage), totalPages);

            if (totalRows === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="empty-state"><p>No scan history available for the selected filters.</p></td></tr>';
                renderHistoryPagination(0, 1, 0, 0);
                return;
            }

            const startIndex = (historyCurrentPage - 1) * historyPageSize;
            const endIndex = Math.min(startIndex + historyPageSize, totalRows);
            const pageRows = rows.slice(startIndex, endIndex);

            tbody.innerHTML = pageRows.map(row => `
                <tr>
                    <td>${new Date(row.analyzedAt).toLocaleString()}</td>
                    <td><a href="${escapeHtml(row.url)}" target="_blank">${escapeHtml(String(row.url || '').substring(0, 64))}${String(row.url || '').length > 64 ? '...' : ''}</a></td>
                    <td><span class="badge ${String(row.status || '').toLowerCase().includes('suspicious') ? 'suspicious' : escapeHtml(row.machineStatus || row.status)}">${escapeHtml(String(row.status).toUpperCase())}</span></td>
                    <td>${Number(row.confidence || 0).toFixed(2)}%</td>
                    <td>${escapeHtml(row.riskLevel || mapRiskFromStatus(row.status))}</td>
                    <td>
                        <div class="history-action-btns">
                            <button
                                class="btn-mini"
                                data-history-action="view"
                                data-history-key="${escapeHtml(row.key)}"
                                data-history-report-id="${escapeHtml(row.reportId || '')}"
                                data-history-report-url="${escapeHtml(row.reportUrl || '')}"
                                ${!row.reportUrl && row.isRemote ? 'disabled title="Report is not available for this history item."' : ''}
                            >View</button>
                            <a class="btn-mini" style="text-decoration:none;" ${row.reportUrl ? `href="${escapeHtml(row.reportUrl)}" target="_blank"` : 'aria-disabled="true"'}>${row.reportUrl ? 'Download' : 'Unavailable'}</a>
                        </div>
                    </td>
                </tr>
            `).join('');
            renderHistoryPagination(totalRows, totalPages, startIndex, endIndex);
        }

        async function loadHistory() {
            const saveHistoryPref = getPreference('shieldurl_pref_save_history', 'enabled');
            const tbody = document.getElementById('historyTableBody');
            if (saveHistoryPref === 'disabled') {
                tbody.innerHTML = '<tr><td colspan="6" class="empty-state"><p>History saving is disabled in Preferences.</p></td></tr>';
                renderHistoryPagination(0, 1, 0, 0);
                return;
            }

            try {
                const response = await fetch('api/get_analysis.php');
                const history = await parseJsonResponse(response);

                const remoteRows = (Array.isArray(history) ? history : [])
                    .map(entry => ({
                        key: `remote-${entry.id || entry.analyzed_at || Math.random()}`,
                        reportId: entry.id || null,
                        analyzedAt: entry.analyzed_at,
                        url: entry.url,
                        status: entry.display_status || entry.status,
                        machineStatus: entry.status,
                        confidence: Number(entry.confidence_score || 0) * 100,
                        riskLevel: mapRiskFromStatus(entry.status),
                        reportUrl: entry.id ? `api/download_report.php?id=${entry.id}` : '',
                        isRemote: true
                    }));

                historyRowsCache = [...localScanHistory, ...remoteRows];
                renderHistoryTable();
            } catch (error) {
                console.error('Error loading history:', error);
                document.getElementById('historyTableBody').innerHTML = '<tr><td colspan="6" style="color: red; text-align: center;">Error loading history</td></tr>';
                renderHistoryPagination(0, 1, 0, 0);
            }
        }

        // Add filter listener
        function applyHistoryFilters() {
            historyCurrentPage = 1;
            renderHistoryTable();
        }

        ['historySearch', 'historyFilter', 'historySort', 'historyDateFrom', 'historyDateTo'].forEach(id => {
            document.getElementById(id)?.addEventListener(id === 'historySearch' ? 'input' : 'change', applyHistoryFilters);
        });
        document.getElementById('historyRefreshBtn').addEventListener('click', (event) => {
            event.preventDefault();
            loadHistory();
        });
        document.getElementById('historyResetBtn').addEventListener('click', (event) => {
            event.preventDefault();
            ['historySearch', 'historyFilter', 'historyDateFrom', 'historyDateTo'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.value = '';
            });
            document.getElementById('historySort').value = 'newest';
            historyCurrentPage = 1;
            renderHistoryTable();
        });
        document.getElementById('historyPageControls').addEventListener('click', (event) => {
            const button = event.target.closest('[data-history-page]');
            if (!button || button.disabled) return;
            historyCurrentPage = Number(button.dataset.historyPage || 1);
            renderHistoryTable();
        });
        document.getElementById('historyTableBody').addEventListener('click', (event) => {
            const button = event.target.closest('[data-history-action="view"]');
            if (!button) return;
            const key = button.getAttribute('data-history-key');
            const reportId = Number(button.getAttribute('data-history-report-id') || 0);
            const reportUrl = button.getAttribute('data-history-report-url') || '';
            if (reportId > 0) {
                openScanDetailFromReport(reportId).catch(error => {
                    alert(error.message || 'Unable to load scan result details.');
                });
                return;
            }
            if (key && scanResultSnapshots[key]) {
                openScanDetailFromSnapshot(key);
                return;
            }
            if (reportUrl) { // fallback if id is unavailable
                window.open(reportUrl, '_blank', 'noopener');
            }
        });
        document.getElementById('scanDetailCloseBtn').addEventListener('click', closeScanDetailModal);
        document.getElementById('scanDetailModal').addEventListener('click', (event) => {
            if (event.target.id === 'scanDetailModal') closeScanDetailModal();
        });
        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape') closeScanDetailModal();
        });

        document.querySelectorAll('.dashboard-tab-btn').forEach(button => {
            button.addEventListener('click', () => switchDashboardTab(button.dataset.tabTarget));
        });

        // Load initial data
        window.addEventListener('load', () => {
            loadHistory();
            switchDashboardTab('tab-check-url');
        });

        const profilePhotoInput = document.getElementById('profilePhotoInput');
        const profilePhotoError = document.getElementById('profilePhotoError');
        if (profilePhotoInput) {
            profilePhotoInput.addEventListener('change', () => {
                profilePhotoError.style.display = 'none';
                profilePhotoError.textContent = '';
                const file = profilePhotoInput.files && profilePhotoInput.files[0];
                if (!file) return;
                const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png'];
                if (!allowedTypes.includes(file.type)) {
                    profilePhotoError.textContent = 'Please upload only JPG, JPEG, or PNG image files.';
                    profilePhotoError.style.display = 'block';
                    profilePhotoInput.value = '';
                    return;
                }
                const reader = new FileReader();
                reader.onload = (event) => {
                    const imageData = String(event.target.result || '');
                    localStorage.setItem(profilePhotoStorageKey, imageData);
                    updateHeaderProfilePhoto(imageData);
                };
                reader.readAsDataURL(file);
            });
        }

        const changePasswordForm = document.getElementById('changePasswordForm');
        if (changePasswordForm) {
            document.querySelectorAll('.password-hold-btn[data-password-target]').forEach((button) => {
                const input = document.getElementById(button.dataset.passwordTarget);
                if (!input) return;
                const reveal = (event) => {
                    event.preventDefault();
                    input.type = 'text';
                    button.classList.add('is-holding');
                };
                const hide = () => {
                    input.type = 'password';
                    button.classList.remove('is-holding');
                };
                button.addEventListener('pointerdown', reveal);
                button.addEventListener('pointerup', hide);
                button.addEventListener('pointerleave', hide);
                button.addEventListener('pointercancel', hide);
                button.addEventListener('blur', hide);
                button.addEventListener('keydown', (event) => {
                    if (event.key === ' ' || event.key === 'Enter') {
                        reveal(event);
                    }
                });
                button.addEventListener('keyup', hide);
            });

            changePasswordForm.addEventListener('submit', async (event) => {
                event.preventDefault();
                const currentPassword = document.getElementById('currentPassword').value;
                const newPassword = document.getElementById('newPassword').value;
                const confirmPassword = document.getElementById('confirmPassword').value;
                const passwordError = document.getElementById('passwordError');
                const passwordInfo = document.getElementById('passwordInfo');
                const submitButton = changePasswordForm.querySelector('button[type="submit"]');
                passwordError.style.display = 'none';
                passwordInfo.textContent = '';
                if (!currentPassword || !newPassword || !confirmPassword) {
                    passwordError.textContent = 'Please complete all password fields.';
                    passwordError.style.display = 'block';
                    return;
                }
                if (newPassword.length < 8) {
                    passwordError.textContent = 'New password must be at least 8 characters.';
                    passwordError.style.display = 'block';
                    return;
                }
                if (newPassword !== confirmPassword) {
                    passwordError.textContent = 'Confirm password must match new password.';
                    passwordError.style.display = 'block';
                    return;
                }
                try {
                    if (submitButton) {
                        submitButton.disabled = true;
                        submitButton.textContent = 'Updating...';
                    }
                    const response = await fetch('api/update_password.php', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        credentials: 'same-origin',
                        body: JSON.stringify({
                            current_password: currentPassword,
                            new_password: newPassword,
                            confirm_password: confirmPassword
                        })
                    });
                    const result = await parseJsonResponse(response);
                    if (!result.success) {
                        throw new Error(result.message || 'Password update failed.');
                    }
                    changePasswordForm.reset();
                    passwordInfo.textContent = result.message || 'Your password has been changed successfully.';
                    window.alert('Your password has been changed successfully.');
                } catch (error) {
                    passwordError.textContent = error.message || 'Password update failed.';
                    passwordError.style.display = 'block';
                } finally {
                    if (submitButton) {
                        submitButton.disabled = false;
                        submitButton.textContent = 'Update Password';
                    }
                }
            });
        }

        function applyPreferences() {
            const theme = getPreference('shieldurl_pref_theme', 'dark');
            const technicalPref = getPreference('shieldurl_pref_technical', 'collapsed');
            const historyPref = getPreference('shieldurl_pref_save_history', 'enabled');
            const sessionTimeoutPref = getPreference('shieldurl_pref_session_timeout_minutes', '30');
            const savedPhoto = getPreference(profilePhotoStorageKey, '');
            document.getElementById('prefTheme').value = theme;
            document.getElementById('prefHistory').value = historyPref;
            document.getElementById('prefTechnical').value = technicalPref;
            document.getElementById('prefSessionTimeout').value = sessionTimeoutPref;
            document.body.classList.toggle('pref-light-theme', theme === 'light');
            const technicalPanel = document.getElementById('technicalDetailsPanel');
            if (technicalPanel) {
                technicalPanel.open = technicalPref === 'expanded';
            }
            updateHeaderProfilePhoto(savedPhoto);
            const assistantToggleBtnEl = document.getElementById('assistantToggleBtn');
            if (assistantToggleBtnEl) {
                updateAssistantToggleAvailability(Boolean(currentScanContext));
            }
            scheduleInactivityTimeout();
        }

        document.getElementById('savePreferencesBtn').addEventListener('click', () => {
            const theme = document.getElementById('prefTheme').value;
            const technicalPref = document.getElementById('prefTechnical').value;
            const historyPref = document.getElementById('prefHistory').value;
            const sessionTimeoutPref = document.getElementById('prefSessionTimeout').value;
            localStorage.setItem('shieldurl_pref_theme', theme);
            localStorage.setItem('shieldurl_pref_technical', technicalPref);
            localStorage.setItem('shieldurl_pref_save_history', historyPref);
            localStorage.setItem('shieldurl_pref_session_timeout_minutes', sessionTimeoutPref);
            localStorage.removeItem('shieldurl_pref_assistant_response_style');
            applyPreferences();
            document.getElementById('prefInfo').textContent = 'Preferences saved.';
            fetch('api/log_activity.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    activity_type: 'settings_update',
                    activity_details: `Preferences updated: theme=${theme}, history=${historyPref}, technical=${technicalPref}, timeout=${sessionTimeoutPref}`
                })
            }).catch(() => {});
        });
        applyPreferences();
        document.getElementById('sessionTimeoutOkBtn').addEventListener('click', () => {
            window.location.href = 'auth/logout.php';
        });
        ['mousemove', 'keydown', 'click', 'scroll'].forEach((eventName) => {
            window.addEventListener(eventName, () => {
                if (!sessionExpiredShown) {
                    scheduleInactivityTimeout();
                }
            }, { passive: eventName === 'scroll' });
        });

        const downloadReportBtn = document.getElementById('downloadReportBtn');
        const downloadReportLabel = document.getElementById('downloadReportLabel');
        if (downloadReportBtn) {
            downloadReportBtn.addEventListener('click', () => {
                if (!downloadReportBtn.href || downloadReportBtn.href.endsWith('#')) {
                    return;
                }
                downloadReportBtn.classList.remove('is-success');
                downloadReportBtn.classList.add('is-loading');
                if (downloadReportLabel) {
                    downloadReportLabel.textContent = 'Preparing report...';
                }
                setTimeout(() => {
                    downloadReportBtn.classList.remove('is-loading');
                    downloadReportBtn.classList.add('is-success');
                    if (downloadReportLabel) {
                        downloadReportLabel.textContent = '✔ Report downloaded';
                    }
                }, 1200);
            });
        }

        const header = document.querySelector('.user-header');
        const headerSpacer = document.querySelector('.header-spacer');
        if (header) {
            const toggleHeader = () => {
                const show = window.scrollY > 120;
                if (show) {
                    header.classList.add('is-visible');
                    if (headerSpacer) {
                        headerSpacer.style.height = `${header.offsetHeight}px`;
                    }
                } else {
                    header.classList.remove('is-visible');
                    header.classList.remove('scrolled');
                    if (headerSpacer) {
                        headerSpacer.style.height = '0px';
                    }
                }

                if (window.scrollY > 180) {
                    header.classList.add('scrolled');
                } else {
                    header.classList.remove('scrolled');
                }
            };
            toggleHeader();
            window.addEventListener('scroll', toggleHeader, { passive: true });
            window.addEventListener('resize', toggleHeader);
        }

        if (document.body.classList.contains('has-transition')) {
            const overlay = document.getElementById('transitionOverlay');
            setTimeout(() => {
                if (overlay) {
                    overlay.style.opacity = '0';
                    setTimeout(() => overlay.remove(), 450);
                }
                document.body.classList.remove('has-transition');
                if (history.replaceState) {
                    const url = new URL(window.location.href);
                    url.searchParams.delete('transition');
                    history.replaceState({}, document.title, url.toString());
                }
            }, 900);
        }
</script>
</body>

</html>

