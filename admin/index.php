<?php
require_once '../config/db.php';

if (!isset($_SESSION['user_id']) || ($_SESSION['role'] ?? '') !== 'admin') {
  header("Location: ../auth/login.php");
  exit();
}

$db = new Database();
$conn = $db->getConnection();

$authStmt = $conn->prepare("SELECT force_password_change, mfa_required, mfa_configured FROM users WHERE id=? AND is_active=TRUE LIMIT 1");
$authStmt->execute([$_SESSION['user_id']]);
$authUser = $authStmt->fetch();
if (!$authUser) {
  session_destroy();
  header("Location: ../auth/login.php?err=User not found");
  exit();
}
$_SESSION['force_password_change'] = (bool)$authUser['force_password_change'];
$_SESSION['mfa_required'] = (bool)$authUser['mfa_required'];
$_SESSION['mfa_configured'] = (bool)$authUser['mfa_configured'];
if ($_SESSION['force_password_change']) {
  header("Location: ../auth/change_password.php?first_login=1");
  exit();
}
if ($_SESSION['mfa_required'] && !$_SESSION['mfa_configured']) {
  header("Location: ../auth/mfa_setup.php");
  exit();
}

$stmt = $conn->prepare("SELECT COUNT(*) as total_users FROM users");
$stmt->execute();
$total_users = $stmt->fetch()['total_users'];

$stmt = $conn->prepare("SELECT COUNT(*) as total_urls FROM url_logs");
$stmt->execute();
$total_urls = $stmt->fetch()['total_urls'];

$stmt = $conn->prepare("SELECT COUNT(*) as users_online FROM users WHERE last_login > DATE_SUB(NOW(), INTERVAL 30 MINUTE)");
$stmt->execute();
$users_online = $stmt->fetch()['users_online'];
?>
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Dashboard - ShieldURL</title>
  <link rel="stylesheet" href="../asset/style.css">
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      --shield-main: #1b4f8a;
      --shield-deep: #0b1f3a;
      --shield-glow: rgba(212, 168, 74, 0.45);
      --shield-ring: rgba(212, 168, 74, 0.35);
      --shield-scan: rgba(255, 255, 255, 0.9);
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: radial-gradient(circle at top, #eef2ff 0%, #f8fafc 45%, #fdf7ec 100%);
      color: #333;
    }

    .user-header {
      background: linear-gradient(135deg, #0b1f3a 0%, #123b6d 55%, #1b4f8a 100%);
      color: white;
      padding: 1.5rem 2rem;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
      display: flex;
      justify-content: space-between;
      align-items: center;
      overflow: hidden;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 0.9rem;
    }

    .brand img {
      width: auto;
      height: 84px;
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
      width: min(1760px, calc(100% - 2rem));
      max-width: none;
      margin: 2rem auto;
      padding: 0;
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 1.5rem;
      margin-bottom: 2rem;
    }

    .stat-card,
    .card {
      background: white;
      border-radius: 10px;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
    }

    .stat-card {
      padding: 2rem;
      text-align: center;
    }

    .stat-card h3 {
      color: #666;
      font-size: 0.9rem;
      margin-bottom: 0.5rem;
      text-transform: uppercase;
      letter-spacing: 1px;
    }

    .stat-card .number {
      font-size: 2.5rem;
      font-weight: 700;
      color: #1d4ed8;
    }

    .card {
      padding: 2rem;
      margin-bottom: 2rem;
    }

    .card h2 {
      margin-bottom: 1.5rem;
      color: #333;
      font-size: 1.5rem;
    }

    .dashboard-layout {
      display: grid;
      grid-template-columns: 220px minmax(0, 1fr);
      gap: 1.1rem;
      margin-bottom: 2rem;
    }

    .dashboard-nav {
      background: #0f2747;
      border: 1px solid rgba(191, 219, 254, 0.25);
      border-radius: 16px;
      padding: 0.8rem;
      position: sticky;
      top: 16px;
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
      animation: fadeIn 0.3s ease-in;
    }

    .form-group {
      margin-bottom: 1.5rem;
    }

    .form-group label {
      display: block;
      margin-bottom: 0.5rem;
      font-weight: 600;
      color: #333;
    }

    .form-group input,
    .form-group select,
    .form-group textarea {
      width: 100%;
      padding: 0.8rem;
      border: 1px solid #ddd;
      border-radius: 5px;
      font-size: 1rem;
      font-family: inherit;
    }

    .form-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1rem;
    }

    .check-form .form-row {
      grid-template-columns: 1fr auto;
    }

    .btn-check,
    .btn-submit {
      background: linear-gradient(135deg, #1b4f8a 0%, #d4a84a 100%);
      color: white;
      padding: 0.8rem 2rem;
      border: none;
      border-radius: 5px;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.4rem;
      height: fit-content;
    }

    .btn-check:hover,
    .btn-submit:hover {
      transform: translateY(-2px);
      box-shadow: 0 5px 15px rgba(212, 168, 74, 0.35);
    }

    .btn-check:disabled {
      cursor: not-allowed;
      opacity: 0.65;
      transform: none;
      box-shadow: none;
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

    .dashboard-card,
    .assistant-panel {
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 14px;
      box-shadow: 0 6px 14px rgba(15, 23, 42, 0.07);
    }

    .dashboard-card {
      padding: 1.25rem;
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
      margin-bottom: 0.5rem;
      color: #0b1f3a;
    }

    .action-card ul {
      margin: 0;
      padding-left: 1rem;
      line-height: 1.6;
      color: #334155;
      font-size: 0.97rem;
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

    .result-field {
      margin-bottom: 1.5rem;
    }

    .result-field label,
    .dashboard-card label {
      font-weight: 600;
      color: #666;
      display: block;
      margin-bottom: 0.5rem;
    }

    .result-value {
      font-size: 1.1rem;
      color: #333;
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
      background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
      transition: width 0.3s ease;
    }

    .badge {
      display: inline-block;
      padding: 0.3rem 0.8rem;
      border-radius: 20px;
      font-size: 0.85rem;
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

    .badge.admin {
      background: #bee3f8;
      color: #2c5282;
    }

    .badge.user {
      background: #e6fffa;
      color: #234e52;
    }

    .assistant-panel {
      padding: 0;
      overflow: hidden;
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

    .assistant-header p,
    .assistant-note {
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
    }

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
      line-height: 1.5;
      overflow-wrap: break-word;
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
    }

    .assistant-note {
      padding: 0 1rem 1rem;
      background: #ffffff;
    }

    .download-report-btn.is-loading {
      background: #1e3a8a !important;
      opacity: 0.92;
    }

    .download-report-btn.is-success {
      background: #15803d !important;
    }

    .table-wrapper {
      overflow-x: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
    }

    table thead {
      background: #f7fafc;
      border-bottom: 2px solid #e2e8f0;
    }

    table th,
    table td {
      padding: 1rem;
      text-align: left;
      border-bottom: 1px solid #e2e8f0;
    }

    table th {
      font-weight: 600;
      color: #333;
    }

    table tbody tr:hover {
      background: #f9fafb;
    }

    .audit-card {
      background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
      border: 1px solid #d7e2f0;
      box-shadow: 0 14px 34px rgba(8, 21, 39, 0.14);
    }

    .audit-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 1rem;
      margin-bottom: 1.2rem;
    }

    .audit-header h2 {
      margin-bottom: 0.35rem;
      color: #0b1f3a;
    }

    .audit-subtitle {
      color: #64748b;
      margin: 0;
      line-height: 1.5;
    }

    .audit-filter-grid {
      display: grid;
      gap: 1rem;
      margin-bottom: 1rem;
    }

    .audit-filter-grid.audit-row-1 {
      grid-template-columns: minmax(260px, 1.6fr) minmax(180px, 1fr) minmax(160px, 0.8fr);
    }

    .audit-filter-grid.audit-row-2,
    .audit-filter-grid.audit-row-3 {
      grid-template-columns: repeat(2, minmax(180px, 1fr));
    }

    .audit-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      margin-bottom: 1rem;
    }

    .btn-secondary {
      border: 1px solid #bfdbfe;
      background: #eff6ff;
      color: #1e3a8a;
      box-shadow: none;
    }

    .audit-table-wrapper {
      max-height: 68vh;
      overflow: auto;
      border: 1px solid #dbe4ef;
      border-radius: 12px;
      background: #ffffff;
    }

    .audit-table {
      table-layout: fixed;
      min-width: 1080px;
    }

    .audit-table thead {
      background: #10294a;
      border-bottom: none;
    }

    .audit-table thead th {
      position: sticky;
      top: 0;
      z-index: 2;
      background: #10294a;
      color: #eaf2ff;
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      border-bottom: 1px solid rgba(191, 219, 254, 0.28);
    }

    .audit-table th,
    .audit-table td {
      padding: 0.8rem 0.75rem;
      vertical-align: middle;
    }

    .audit-table tbody tr {
      transition: background 0.16s ease, box-shadow 0.16s ease;
    }

    .audit-table tbody tr:hover {
      background: #eef6ff;
      box-shadow: inset 3px 0 0 #1d4ed8;
    }

    .audit-col-time { width: 168px; }
    .audit-col-user { width: 170px; }
    .audit-col-role { width: 90px; }
    .audit-col-division { width: 145px; }
    .audit-col-activity { width: 165px; }
    .audit-col-ip { width: 135px; }
    .audit-col-country { width: 130px; }
    .audit-col-status { width: 105px; }
    .audit-col-details { width: 95px; }

    .audit-nowrap,
    .audit-user,
    .audit-ellipsis {
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .audit-user {
      font-weight: 700;
      color: #0f2747;
    }

    .audit-table .badge {
      max-width: 100%;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      vertical-align: middle;
    }

    .audit-detail-btn {
      border: 1px solid #bfdbfe;
      border-radius: 8px;
      background: #eff6ff;
      color: #1e3a8a;
      padding: 0.42rem 0.7rem;
      font: inherit;
      font-size: 0.85rem;
      font-weight: 700;
      cursor: pointer;
    }

    .audit-detail-btn:hover {
      background: #dbeafe;
    }

    .audit-modal {
      position: fixed;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      padding: 1rem;
      background: rgba(8, 21, 39, 0.58);
      z-index: 10000;
    }

    .audit-modal.show {
      display: flex;
    }

    .audit-modal-panel {
      width: min(680px, 100%);
      max-height: 82vh;
      overflow: auto;
      background: #ffffff;
      border: 1px solid #dbe4ef;
      border-radius: 14px;
      box-shadow: 0 24px 70px rgba(8, 21, 39, 0.35);
    }

    .audit-modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      padding: 1rem 1.15rem;
      background: #10294a;
      color: #ffffff;
    }

    .audit-modal-header h3 {
      margin: 0;
      font-size: 1rem;
    }

    .audit-modal-close {
      border: 1px solid rgba(255, 255, 255, 0.35);
      background: rgba(255, 255, 255, 0.12);
      color: #ffffff;
      border-radius: 8px;
      padding: 0.35rem 0.65rem;
      cursor: pointer;
      font-weight: 700;
    }

    .audit-modal-body {
      padding: 1.15rem;
      display: grid;
      gap: 0.8rem;
    }

    .audit-modal-row {
      display: grid;
      grid-template-columns: 140px minmax(0, 1fr);
      gap: 0.8rem;
      align-items: start;
    }

    .audit-modal-row strong {
      color: #475569;
      font-size: 0.9rem;
    }

    .audit-modal-row span,
    .audit-modal-row pre {
      margin: 0;
      color: #0f172a;
      white-space: pre-wrap;
      word-break: break-word;
      font-family: inherit;
    }

    .empty-state {
      text-align: center;
      padding: 3rem;
      color: #999;
    }

    .delete-btn {
      background: #fed7d7;
      color: #742a2a;
      border: 1px solid #f56565;
      padding: 0.3rem 0.6rem;
      border-radius: 4px;
      cursor: pointer;
    }

    .history-action-btns {
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
      align-items: center;
    }

    .btn-mini {
      border: 1px solid #bfdbfe;
      border-radius: 8px;
      background: #eff6ff;
      color: #1e3a8a;
      padding: 0.4rem 0.65rem;
      font-weight: 700;
      cursor: pointer;
      font: inherit;
      font-size: 0.85rem;
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

    body.status-safe {
      --shield-main: #48bb78;
      --shield-deep: #2f855a;
      --shield-glow: rgba(72, 187, 120, 0.55);
      --shield-ring: rgba(72, 187, 120, 0.35);
      --shield-scan: rgba(240, 253, 250, 0.95);
    }

    body.status-warn {
      --shield-main: #f6ad55;
      --shield-deep: #c05621;
      --shield-glow: rgba(246, 173, 85, 0.6);
      --shield-ring: rgba(246, 173, 85, 0.4);
      --shield-scan: rgba(255, 251, 235, 0.95);
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

    body.status-warn .shield-visual {
      animation: float 4s ease-in-out infinite, sway 1.8s ease-in-out infinite;
    }

    .shield-visual.bursting .shield-burst {
      animation: burst 0.8s ease-out forwards;
    }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }

    @keyframes slideDown {
      from { opacity: 0; transform: translateY(-20px); }
      to { opacity: 1; transform: translateY(0); }
    }

    @keyframes spin {
      100% { transform: rotate(360deg); }
    }

    @keyframes float {
      0%, 100% { transform: translateY(0); }
      50% { transform: translateY(-8px); }
    }

    @keyframes pulse {
      0% { transform: scale(0.9); opacity: 0.45; }
      70%, 100% { transform: scale(1.1); opacity: 0; }
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

    @media (max-width: 900px) {
      .dashboard-layout,
      .analysis-layout.assistant-open {
        grid-template-columns: 1fr;
      }

      .dashboard-nav {
        position: static;
      }

      .action-grid,
      .summary-grid,
      .form-row,
      .check-form .form-row {
        grid-template-columns: 1fr;
      }

      .audit-filter-grid.audit-row-1,
      .audit-filter-grid.audit-row-2,
      .audit-filter-grid.audit-row-3 {
        grid-template-columns: 1fr;
      }

      .audit-table .audit-hide-tablet {
        display: none;
      }

      .user-header {
        flex-direction: column;
        gap: 1rem;
        text-align: center;
      }
    }

    @media (max-width: 768px) {
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

      .assistant-messages {
        padding: 16px;
      }

      .assistant-input {
        grid-template-columns: 1fr;
        padding: 16px;
      }

      .floating-assistant-icon {
        right: 18px;
        bottom: 18px;
        width: 58px;
        height: 58px;
      }

      .container {
        width: min(100% - 1rem, 1760px);
      }

      .audit-table-wrapper {
        max-height: none;
        overflow: visible;
        border: none;
        background: transparent;
      }

      .audit-table {
        min-width: 0;
        table-layout: auto;
      }

      .audit-table,
      .audit-table thead,
      .audit-table tbody,
      .audit-table th,
      .audit-table td,
      .audit-table tr {
        display: block;
      }

      .audit-table thead {
        display: none;
      }

      .audit-table tbody tr {
        background: #ffffff;
        border: 1px solid #dbe4ef;
        border-radius: 12px;
        box-shadow: 0 8px 18px rgba(15, 23, 42, 0.08);
        margin-bottom: 0.85rem;
        padding: 0.75rem;
      }

      .audit-table tbody tr:hover {
        box-shadow: 0 10px 22px rgba(15, 23, 42, 0.12);
      }

      .audit-table td {
        border-bottom: 1px solid #eef2f7;
        display: grid;
        grid-template-columns: 112px minmax(0, 1fr);
        gap: 0.75rem;
        padding: 0.65rem 0;
      }

      .audit-table td:last-child {
        border-bottom: none;
      }

      .audit-table td::before {
        content: attr(data-label);
        color: #64748b;
        font-size: 0.78rem;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.04em;
      }

      .audit-col-time,
      .audit-col-user,
      .audit-col-role,
      .audit-col-division,
      .audit-col-activity,
      .audit-col-ip,
      .audit-col-country,
      .audit-col-status,
      .audit-col-details {
        width: auto;
      }

      .audit-modal-row {
        grid-template-columns: 1fr;
        gap: 0.25rem;
      }
    }
  </style>
</head>

<body>
  <div class="user-header">
    <div class="brand">
      <img src="../img/logo.png" alt="ShieldURL logo">
      <span class="brand-title">ShieldURL</span>
    </div>
    <div class="user-info">
      <span>Welcome, <strong><?php echo htmlspecialchars($_SESSION['username']); ?></strong></span>
      <a class="logout-btn" href="../auth/logout.php">Logout</a>
    </div>
  </div>

  <div class="container">
    <div class="stats-grid">
      <div class="stat-card">
        <h3>Total Users</h3>
        <div class="number"><?php echo $total_users; ?></div>
      </div>
      <div class="stat-card">
        <h3>URLs Checked</h3>
        <div class="number"><?php echo $total_urls; ?></div>
      </div>
      <div class="stat-card">
        <h3>Users Online</h3>
        <div class="number"><?php echo $users_online; ?></div>
      </div>
    </div>

    <div class="dashboard-layout">
      <aside class="dashboard-nav">
        <button class="dashboard-tab-btn active" data-tab-target="tab-check-url">Check URL</button>
        <button class="dashboard-tab-btn" data-tab-target="tab-history">Scan History</button>
        <button class="dashboard-tab-btn" data-tab-target="tab-users">Users</button>
        <button class="dashboard-tab-btn" data-tab-target="tab-audit">Audit Log</button>
        <button class="dashboard-tab-btn" data-tab-target="tab-settings">Settings</button>
      </aside>

      <section>
        <div class="dashboard-tab-panel active" id="tab-check-url">
          <?php require __DIR__ . '/../shared/check_url_component.php'; ?>
        </div>

        <div class="dashboard-tab-panel" id="tab-history">
          <div class="card">
            <h2>URL Analysis History</h2>
            <div class="form-row" style="margin-bottom: 1.5rem;">
              <div class="form-group">
                <label>Filter by Status</label>
                <select id="historyFilter">
                  <option value="">All</option>
                  <option value="safe">Safe</option>
                  <option value="phishing">Phishing</option>
                  <option value="suspicious">Suspicious</option>
                </select>
              </div>
              <div class="form-group">
                <label>&nbsp;</label>
                <button class="btn-check" id="historyRefreshBtn" type="button">Refresh</button>
              </div>
            </div>

            <div class="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>User</th>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Confidence</th>
                    <th>Analyzed At</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody id="historyTableBody">
                  <tr>
                    <td colspan="7" class="empty-state"><p>No analysis history found</p></td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div class="dashboard-tab-panel" id="tab-users">
          <div class="card">
            <h2>Register New User</h2>
            <form id="registerForm">
              <div class="form-row">
                <div class="form-group">
                  <label for="full_name">Full Name *</label>
                  <input type="text" id="full_name" name="full_name" required>
                </div>
                <div class="form-group">
                  <label for="email">Email *</label>
                  <input type="email" id="email" name="email" required>
                </div>
              </div>

              <div class="form-row">
                <div class="form-group">
                  <label for="phone">Phone</label>
                  <input type="text" id="phone" name="phone">
                </div>
                <div class="form-group">
                  <label for="department">Department</label>
                  <input type="text" id="department" name="department">
                </div>
              </div>

              <div class="form-group">
                <label for="role">Role *</label>
                <select id="role" name="role" required>
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <p class="scan-helper">ShieldURL will generate a secure temporary password, email it to the user, and require password change plus email code verification at first login.</p>

              <button type="submit" class="btn-check">Register User</button>
              <div id="registerResult" class="result-message"></div>
            </form>
          </div>

          <div class="card">
            <h2>Registered Users</h2>
            <div class="table-wrapper">
              <table id="usersTable">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Full Name</th>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Last Login</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody id="usersTableBody">
                  <tr>
                    <td colspan="8" class="empty-state"><p>Loading...</p></td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div class="dashboard-tab-panel" id="tab-audit">
          <div class="card audit-card">
            <div class="audit-header">
              <div>
                <h2>Security Audit Log</h2>
                <p class="audit-subtitle">Monitor authentication, administrative actions, scans, report access, and settings changes.</p>
              </div>
            </div>
            <div class="audit-filter-grid audit-row-1">
              <div class="form-group">
                <label for="auditSearch">Search</label>
                <input type="text" id="auditSearch" placeholder="Username, details, IP, session">
              </div>
              <div class="form-group">
                <label for="auditActivity">Activity</label>
                <select id="auditActivity"><option value="">All</option></select>
              </div>
              <div class="form-group">
                <label for="auditStatus">Status</label>
                <select id="auditStatus">
                  <option value="">All</option>
                  <option value="success">Success</option>
                  <option value="failed">Failed</option>
                </select>
              </div>
            </div>
            <div class="audit-filter-grid audit-row-2">
              <div class="form-group">
                <label for="auditDateFrom">From</label>
                <input type="date" id="auditDateFrom">
              </div>
              <div class="form-group">
                <label for="auditDateTo">To</label>
                <input type="date" id="auditDateTo">
              </div>
            </div>
            <div class="audit-filter-grid audit-row-3">
              <div class="form-group">
                <label for="auditDivision">Division</label>
                <select id="auditDivision"><option value="">All</option></select>
              </div>
              <div class="form-group">
                <label for="auditCountry">Country</label>
                <select id="auditCountry"><option value="">All</option></select>
              </div>
            </div>
            <div class="audit-actions">
              <button class="btn-check" id="auditRefreshBtn" type="button">Apply Filters</button>
              <button class="btn-check btn-secondary" id="auditResetBtn" type="button">Reset Filters</button>
            </div>
            <div class="table-wrapper audit-table-wrapper">
              <table class="audit-table">
                <thead>
                  <tr>
                    <th class="audit-col-time">Timestamp</th>
                    <th class="audit-col-user">User</th>
                    <th class="audit-col-role">Role</th>
                    <th class="audit-col-division audit-hide-tablet">Division</th>
                    <th class="audit-col-activity">Activity</th>
                    <th class="audit-col-ip">IP Address</th>
                    <th class="audit-col-country audit-hide-tablet">Country</th>
                    <th class="audit-col-status">Status</th>
                    <th class="audit-col-details">Details</th>
                  </tr>
                </thead>
                <tbody id="auditTableBody">
                  <tr>
                    <td colspan="9" class="empty-state"><p>No audit logs found</p></td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div class="dashboard-tab-panel" id="tab-settings">
          <div class="card">
            <h2>Settings</h2>
            <div class="dashboard-card">
              <p>Admin account settings remain managed through the existing authentication and database controls.</p>
              <p style="margin-top: 0.75rem; color: #64748b;">URL detection and ShieldURL Assistant use the same interface as the user dashboard.</p>
            </div>
          </div>
        </div>
      </section>
    </div>
  </div>

  <div class="audit-modal" id="auditDetailModal" aria-hidden="true">
    <div class="audit-modal-panel" role="dialog" aria-modal="true" aria-labelledby="auditDetailTitle">
      <div class="audit-modal-header">
        <h3 id="auditDetailTitle">Audit Event Details</h3>
        <button class="audit-modal-close" id="auditModalCloseBtn" type="button">Close</button>
      </div>
      <div class="audit-modal-body" id="auditModalBody"></div>
    </div>
  </div>

  <div class="audit-modal" id="scanDetailModal" aria-hidden="true">
    <div class="audit-modal-panel" role="dialog" aria-modal="true" aria-labelledby="scanDetailTitle">
      <div class="audit-modal-header">
        <h3 id="scanDetailTitle">Scan Result Details</h3>
        <button class="audit-modal-close" id="scanModalCloseBtn" type="button">Close</button>
      </div>
      <div class="audit-modal-body" id="scanModalBody"></div>
    </div>
  </div>

  <script>
    let currentScanId = null;
    let currentScanContext = null;
    let assistantIsLoading = false;
    let assistantPanelOpen = false;
    let hasScanResult = false;
    let isScanRunning = false;
    let auditLogCache = {};

    async function parseJsonResponse(response) {
      const text = await response.text();
      let data = null;
      if (text.trim() !== '') {
        try {
          data = JSON.parse(text);
        } catch (error) {
          throw new Error('Backend did not return valid JSON: ' + text);
        }
      }
      if (!response.ok) {
        throw new Error((data && (data.error || data.detail || data.message)) || ('Request failed with status ' + response.status));
      }
      return data;
    }

    function escapeHtml(value) {
      return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
    }

    function auditActivityLabel(value) {
      return String(value || '-').replaceAll('_', ' ').replace(/\b\w/g, char => char.toUpperCase());
    }

    function normalizeToList(value) {
      if (Array.isArray(value)) return value.filter(item => item !== null && item !== undefined && String(item).trim() !== '');
      if (typeof value === 'string' && value.trim() !== '') {
        try {
          const parsed = JSON.parse(value);
          return Array.isArray(parsed) ? parsed : [value.trim()];
        } catch (error) {
          return [value.trim()];
        }
      }
      return [];
    }

    function collectList(...values) {
      return values.flatMap(normalizeToList);
    }

    function formatProbabilityValue(value) {
      if (typeof value === 'string' && value.includes('%')) return value;
      const numeric = Number(value || 0);
      const percent = numeric <= 1 ? numeric * 100 : numeric;
      return Number.isFinite(percent) ? percent.toFixed(2) + '%' : 'Not Collected';
    }

    function simplePolicyText(value) {
      const text = String(value || '').trim();
      if (!text || /lexical model|false negatives|threshold|recall/i.test(text)) {
        return 'The system uses advanced URL detection analysis to identify suspicious website patterns.';
      }
      return text;
    }

    function updateModelDecisionExplanation(data) {
      const probability = data?.phishing_probability ?? data?.ml?.phishing_probability ?? data?.detection?.phishing_probability ?? data?.confidence_score ?? data?.detection?.confidence_score;
      const threshold = data?.selected_threshold ?? data?.ml?.selected_threshold ?? data?.detection?.lexical_threshold;
      const finalVerdict = data?.status ?? data?.detection?.final_verdict ?? data?.overall?.status ?? 'unknown';
      const displayVerdict = data?.display_status ?? data?.overall?.display_verdict ?? data?.detection?.display_verdict ?? finalVerdict;
      const policy = simplePolicyText(data?.model_policy ?? data?.overall?.model_policy ?? data?.ml?.model_policy ?? data?.detection?.model_policy);

      document.getElementById('modelPhishingProbability').textContent = formatProbabilityValue(probability);
      document.getElementById('modelSelectedThreshold').textContent = threshold === undefined || threshold === null || threshold === '' ? 'Not Collected' : formatProbabilityValue(threshold);
      document.getElementById('modelFinalVerdict').textContent = String(finalVerdict).replaceAll('_', ' ').toUpperCase();
      document.getElementById('modelDisplayVerdict').textContent = String(displayVerdict).replaceAll('_', ' ').toUpperCase();
      document.getElementById('modelPolicyText').textContent = policy;
    }

    function renderSimpleList(containerId, items, emptyMessage) {
      const container = document.getElementById(containerId);
      if (!container) return;
      container.innerHTML = '';
      if (!items || !items.length) {
        const li = document.createElement('li');
        li.textContent = emptyMessage;
        container.appendChild(li);
        return;
      }
      items.forEach(item => {
        const li = document.createElement('li');
        li.textContent = typeof item === 'string' ? item : JSON.stringify(item);
        container.appendChild(li);
      });
    }

    function formatMitreTag(tech) {
      if (typeof tech === 'string') return tech;
      if (!tech || typeof tech !== 'object') return JSON.stringify(tech);
      const id = tech.id || tech.technique_id || tech.tactic_id || '';
      const name = tech.name || tech.technique_name || tech.technique || tech.tactic || '';
      return [id, name].filter(Boolean).join(' - ') || JSON.stringify(tech);
    }

    function mapRiskFromStatus(status) {
      const normalized = String(status || '').toLowerCase();
      if (normalized === 'phishing') return 'High Risk';
      if (normalized === 'suspicious' || normalized.includes('suspicious')) return 'Medium Risk';
      return 'Low Risk';
    }

    function switchDashboardTab(tabId) {
      document.querySelectorAll('.dashboard-tab-btn').forEach(button => {
        button.classList.toggle('active', button.dataset.tabTarget === tabId);
      });
      document.querySelectorAll('.dashboard-tab-panel').forEach(panel => {
        panel.classList.toggle('active', panel.id === tabId);
      });
      if (tabId === 'tab-history') loadHistory();
      if (tabId === 'tab-users') loadUsers();
    }

    function setScanInteractionState({ inputDisabled, buttonDisabled, buttonLabel }) {
      document.getElementById('url').disabled = Boolean(inputDisabled);
      const scanBtn = document.getElementById('scanActionBtn');
      scanBtn.disabled = Boolean(buttonDisabled);
      scanBtn.textContent = buttonLabel;
    }

    function resetScanViewForRecheck() {
      document.getElementById('analysisResult').classList.remove('show');
      document.getElementById('checkResult').className = 'result-message';
      document.getElementById('checkResult').textContent = '';
      document.getElementById('url').value = '';
      document.body.classList.remove('status-scanning', 'status-safe', 'status-warn', 'status-danger');
      resetAssistant(null);
      hasScanResult = false;
      isScanRunning = false;
      setScanInteractionState({ inputDisabled: false, buttonDisabled: false, buttonLabel: 'Scan URL' });
      document.getElementById('url').focus();
    }

    function askClickedStatus() {
      const modal = document.getElementById('clickedUrlModal');
      const yesBtn = document.getElementById('clickedYesBtn');
      const noBtn = document.getElementById('clickedNoBtn');

      if (!modal || typeof modal.showModal !== 'function') {
        return Promise.resolve(window.confirm('Have you already clicked this URL?'));
      }

      return new Promise((resolve) => {
        const cleanup = () => {
          yesBtn.removeEventListener('click', onYes);
          noBtn.removeEventListener('click', onNo);
          modal.removeEventListener('cancel', onCancel);
        };
        const onYes = () => { cleanup(); modal.close(); resolve(true); };
        const onNo = () => { cleanup(); modal.close(); resolve(false); };
        const onCancel = () => { cleanup(); resolve(false); };
        yesBtn.addEventListener('click', onYes);
        noBtn.addEventListener('click', onNo);
        modal.addEventListener('cancel', onCancel);
        modal.showModal();
      });
    }

    function updateShieldState(status) {
      const normalized = String(status || 'safe').toLowerCase();
      const mode = normalized.includes('suspicious') ? 'warn' : (normalized === 'phishing' ? 'danger' : 'safe');
      const copy = {
        safe: ['SAFE', 'Shield locked: safe', 'Protection is stable and the URL looks clean.'],
        warn: ['WARN', 'Review carefully', 'Suspicious signals detected, but this URL is not confirmed as phishing. Review the URL carefully before interacting with it.'],
        danger: ['BLOCK', 'Shield blocking threats', 'High-risk signals detected. Avoid this link.']
      };
      document.body.classList.remove('status-scanning', 'status-safe', 'status-warn', 'status-danger');
      document.body.classList.add('status-' + mode);
      document.getElementById('shieldLabel').textContent = copy[mode][0];
      document.getElementById('shieldTitle').textContent = copy[mode][1];
      document.getElementById('shieldSubtitle').textContent = copy[mode][2];
      const shieldVisual = document.querySelector('.shield-visual');
      if (shieldVisual) {
        shieldVisual.classList.remove('bursting');
        void shieldVisual.offsetWidth;
        shieldVisual.classList.add('bursting');
        setTimeout(() => shieldVisual.classList.remove('bursting'), 900);
      }
    }

    function setAssistantPanelOpen(isOpen) {
      const assistantColumn = document.getElementById('assistantColumn');
      const assistantOverlay = document.getElementById('assistantOverlay');
      const toggleBtn = document.getElementById('assistantToggleBtn');
      const toggleLabel = document.getElementById('assistantToggleLabel');
      assistantPanelOpen = Boolean(isOpen);
      if (assistantColumn) assistantColumn.classList.toggle('assistant-open', assistantPanelOpen);
      if (assistantOverlay) assistantOverlay.setAttribute('aria-hidden', assistantPanelOpen ? 'false' : 'true');
      if (toggleBtn) toggleBtn.style.display = assistantPanelOpen ? 'none' : 'inline-flex';
      if (toggleLabel) toggleLabel.textContent = 'Open ShieldURL Assistant';
      if (assistantPanelOpen) {
        setTimeout(() => document.getElementById('assistantInput')?.focus(), 180);
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
      if (!toggleBtn) return;
      toggleBtn.style.display = assistantPanelOpen ? 'none' : 'inline-flex';
      toggleBtn.disabled = false;
      if (toggleLabel) toggleLabel.textContent = 'Open ShieldURL Assistant';
      setAssistantPanelOpen(false);
    }

    function appendAssistantMessage(role, text) {
      const messages = document.getElementById('assistantMessages');
      if (!messages) return null;
      const emptyNotice = messages.querySelector('.assistant-message.notice');
      if (emptyNotice) emptyNotice.remove();
      const bubble = document.createElement('div');
      bubble.className = 'assistant-message ' + role;
      bubble.textContent = text;
      messages.appendChild(bubble);
      messages.scrollTop = messages.scrollHeight;
      return bubble;
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

    function setAssistantEnabled(enabled) {
      document.getElementById('assistantInput').disabled = !enabled || assistantIsLoading;
      document.getElementById('assistantSendBtn').disabled = !enabled || assistantIsLoading;
      document.querySelectorAll('.assistant-starter').forEach(button => {
        button.disabled = !enabled || assistantIsLoading;
      });
    }

    function resetAssistant(scanId, scanContext = null) {
      currentScanId = scanId || null;
      currentScanContext = scanContext || null;
      const hasContext = Boolean(currentScanContext);
      const messages = document.getElementById('assistantMessages');
      if (messages) {
        messages.innerHTML = '';
        appendAssistantMessage('assistant', 'Welcome. I am ShieldURL Assistant. How can I help you today?');
        if (!hasContext) appendAssistantMessage('notice', 'Please scan a URL first before using the assistant.');
      }
      document.getElementById('assistantInput').value = '';
      setAssistantEnabled(hasContext);
      updateAssistantToggleAvailability(hasContext);
    }

    async function sendAssistantQuestion(question) {
      const trimmed = String(question || '').trim();
      if (!currentScanContext) {
        appendAssistantMessage('notice', 'Please scan a URL first before using the assistant.');
        return;
      }
      if (!trimmed) return;
      if (trimmed.length > 500) {
        appendAssistantMessage('assistant', 'Please keep questions to 500 characters or fewer.');
        return;
      }

      appendAssistantMessage('user', trimmed);
      assistantIsLoading = true;
      setAssistantEnabled(true);
      const loadingBubble = appendAssistantMessage('assistant', 'ShieldURL Assistant is analyzing the scan context...');

      try {
        const conversation = getAssistantConversation();
        const response = await fetch('../api/chat.php', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            scan_id: currentScanId,
            message: trimmed,
            assistant_response_style: 'simple',
            scan_context: currentScanContext,
            history: conversation,
            conversation,
          })
        });
        const result = await parseJsonResponse(response);
        loadingBubble.textContent = result.answer || 'The assistant is temporarily unavailable, but the scan result remains valid. Please follow the recommended actions.';
      } catch (error) {
        loadingBubble.textContent = 'The assistant is temporarily unavailable, but the scan result remains valid. Please follow the recommended actions.';
      } finally {
        assistantIsLoading = false;
        setAssistantEnabled(Boolean(currentScanContext));
        document.getElementById('assistantInput').value = '';
        document.getElementById('assistantInput').focus();
      }
    }

    document.getElementById('assistantForm').addEventListener('submit', (event) => {
      event.preventDefault();
      sendAssistantQuestion(document.getElementById('assistantInput').value);
    });

    document.querySelectorAll('.assistant-starter').forEach(button => {
      button.addEventListener('click', () => sendAssistantQuestion(button.textContent));
    });

    document.getElementById('assistantToggleBtn').addEventListener('click', () => {
      setAssistantPanelOpen(!assistantPanelOpen);
    });
    document.getElementById('assistantCloseBtn')?.addEventListener('click', () => setAssistantPanelOpen(false));
    document.getElementById('assistantOverlay')?.addEventListener('click', () => setAssistantPanelOpen(false));
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && assistantPanelOpen) setAssistantPanelOpen(false);
    });

    mountAssistantToViewport();

    document.getElementById('checkUrlForm').addEventListener('submit', async (event) => {
      event.preventDefault();
      if (isScanRunning) return;
      if (hasScanResult) {
        resetScanViewForRecheck();
        return;
      }

      const url = document.getElementById('url').value;
      const clicked = await askClickedStatus();
      const resultDiv = document.getElementById('checkResult');
      resultDiv.className = 'result-message loading';
      resultDiv.innerHTML = '<span class="loading-spinner" aria-hidden="true"></span><span>Analyzing URL detection...</span>';
      isScanRunning = true;
      resetAssistant(null);
      setScanInteractionState({ inputDisabled: true, buttonDisabled: true, buttonLabel: 'Scanning...' });
      document.body.classList.remove('status-safe', 'status-warn', 'status-danger');
      document.body.classList.add('status-scanning');
      document.getElementById('shieldLabel').textContent = 'SCAN';
      document.getElementById('shieldTitle').textContent = 'Scanning signals';
      document.getElementById('shieldSubtitle').textContent = 'Shield is sweeping for phishing patterns.';

      try {
        const response = await fetch('../api/analyze.php', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url, clicked })
        });
        const result = await parseJsonResponse(response);
        const detection = result.detection && typeof result.detection === 'object' ? result.detection : {};
        const isSuccessfulScan = result.success === true || Object.keys(detection).length > 0 || result.overall || result.ml;

        if (!isSuccessfulScan) {
          throw new Error(result.message || 'Analysis failed. Please try again.');
        }

        resultDiv.className = 'result-message success';
        const modelPolicy = simplePolicyText(result.model_policy || result.overall?.model_policy || result.ml?.model_policy);
        resultDiv.textContent = 'Analysis completed. ' + modelPolicy;

        const displayUrl = result.url || detection.url || url;
        document.getElementById('resultUrl').href = displayUrl;
        document.getElementById('resultUrl').textContent = displayUrl;

        const rawConfidence = Number(result.phishing_probability ?? result.confidence_score ?? detection.phishing_probability ?? detection.confidence_score ?? 0);
        const confidence = rawConfidence <= 1 ? rawConfidence * 100 : rawConfidence;
        document.getElementById('confidenceScore').textContent = confidence.toFixed(2) + '%';
        document.getElementById('confidenceFill').style.width = Math.max(0, Math.min(100, confidence)) + '%';
        updateModelDecisionExplanation(result);

        const status = String(result.status || detection.final_verdict || result.overall?.status || 'safe').toLowerCase();
        const riskLevel = String(result.risk_level || detection.risk_level || result.overall?.risk_level || mapRiskFromStatus(status));
        document.getElementById('riskLevelValue').textContent = riskLevel.replaceAll('_', ' ').replace(/\b\w/g, c => c.toUpperCase());

        const features = result.features || detection.features || {};
        document.getElementById('analysisDetails').textContent = JSON.stringify(features, null, 2);
        document.getElementById('analyzedTime').textContent = new Date().toLocaleString();

        const llmReport = result.llm_report && typeof result.llm_report === 'object' ? result.llm_report : {};
        const llmBridge = result.llm && typeof result.llm === 'object' ? result.llm : {};
        const llmResponse = result.llm_response && typeof result.llm_response === 'object' ? result.llm_response : {};
        const llm = Object.keys(llmReport).length ? llmReport : (Object.keys(llmBridge).length ? llmBridge : llmResponse);

        const displayStatusText = result.display_status || result.overall?.display_verdict || detection.display_verdict || status;
        const incidentSummary = String(displayStatusText).toLowerCase().includes('potentially suspicious')
          ? 'This URL shows suspicious characteristics, but it is not confirmed phishing. Users should verify the website carefully before entering passwords, OTPs, or sensitive information.'
          : (llm.incident_summary || llm.executive_summary || result.llm_summary || `The submitted URL was classified as ${displayStatusText} with ${riskLevel.toLowerCase()} risk based on the scan result. The system uses advanced URL detection analysis to identify suspicious website patterns.`);
        document.getElementById('llmSummary').textContent = incidentSummary;

        const containmentActions = collectList(llm.containment_actions, result.containment_actions);
        const eradicationActions = collectList(llm.eradication_recovery_actions, result.eradication_recovery_actions);
        const postIncidentActions = collectList(llm.post_incident_recommendations, result.post_incident_recommendations);
        const fallbackIncident = collectList(llm.incident_response, result.incident_response);
        renderSimpleList('containmentList', containmentActions.length ? containmentActions : fallbackIncident, 'No containment steps provided.');
        renderSimpleList('eradicationList', eradicationActions, 'No eradication and recovery steps provided.');
        renderSimpleList('postIncidentList', postIncidentActions, 'No post-incident recommendations provided.');
        document.getElementById('userAdvisory').textContent = llm.user_advisory || result.user_advisory || 'Review the URL carefully before interacting with it. Verify the destination before entering login details, OTP, banking information, or personal data.';

        const mitreMapping = collectList(llm.mitre_attack_mapping, result.mitre_attack_mapping, llm.mitre_techniques, result.mitre_techniques);
        const mitreContainer = document.getElementById('mitreTags');
        mitreContainer.innerHTML = '';
        mitreMapping.forEach(tech => {
          const span = document.createElement('span');
          span.className = 'badge';
          span.style.background = '#e2e8f0';
          span.style.color = '#4a5568';
          span.textContent = formatMitreTag(tech);
          mitreContainer.appendChild(span);
        });
        document.getElementById('mitrePrimaryValue').textContent = mitreMapping.length ? formatMitreTag(mitreMapping[0]) : '-';

        const downloadBtn = document.getElementById('downloadReportBtn');
        const downloadLabel = document.getElementById('downloadReportLabel');
        if (result.report_id) {
          downloadBtn.href = '../api/download_report.php?id=' + encodeURIComponent(result.report_id);
          downloadBtn.style.display = 'inline-flex';
          downloadBtn.classList.remove('is-loading', 'is-success');
          downloadLabel.textContent = 'Download Report';
        } else {
          downloadBtn.style.display = 'none';
        }

        const statusBadge = document.getElementById('statusBadge');
        const displayStatusClass = String(displayStatusText).toLowerCase().includes('suspicious') ? 'suspicious' : status;
        statusBadge.className = 'badge ' + displayStatusClass;
        statusBadge.textContent = String(displayStatusText).toUpperCase();

        const latestScanContext = {
          checked_url: displayUrl,
          detection: {
            final_verdict: status,
            display_verdict: displayStatusText,
            confidence_score: rawConfidence,
            phishing_probability: Number(result.phishing_probability ?? detection.phishing_probability ?? 0),
            selected_threshold: Number(result.selected_threshold ?? result.ml?.selected_threshold ?? detection.lexical_threshold ?? 0.5),
            model_policy: modelPolicy,
            risk_level: riskLevel
          },
          suspicious_indicators: collectList(result.heuristics?.reasons, detection.heuristic_reasons, detection.suspicious_indicators),
          extracted_features: features,
          mitre_attack: mitreMapping,
          nist_actions: {
            containment: containmentActions,
            eradication_recovery: eradicationActions,
            post_incident: postIncidentActions
          },
          user_advisory: document.getElementById('userAdvisory').textContent
        };

        resetAssistant(result.report_id, latestScanContext);
        document.getElementById('analysisResult').classList.add('show');
        hasScanResult = true;
        isScanRunning = false;
        setScanInteractionState({ inputDisabled: true, buttonDisabled: false, buttonLabel: 'Recheck URL' });
        updateShieldState(displayStatusText || status);
        if (result.llm_pending && result.report_id) {
          document.getElementById('llmSummary').textContent = 'AI report is being prepared. The URL safety result is already available.';
          fetch('../api/generate_report.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ report_id: result.report_id })
          })
            .then(parseJsonResponse)
            .then(reportResult => {
              const generated = reportResult.llm_report && typeof reportResult.llm_report === 'object' ? reportResult.llm_report : {};
              if (!reportResult.success || !Object.keys(generated).length) return;
              document.getElementById('llmSummary').textContent = String(displayStatusText).toLowerCase().includes('potentially suspicious')
                ? 'This URL shows suspicious characteristics, but it is not confirmed phishing. Users should verify the website carefully before entering passwords, OTPs, or sensitive information.'
                : (generated.incident_summary || 'AI report is ready.');
              renderSimpleList('containmentList', collectList(generated.containment_actions), 'No containment steps provided.');
              renderSimpleList('eradicationList', collectList(generated.eradication_recovery_actions), 'No eradication and recovery steps provided.');
              renderSimpleList('postIncidentList', collectList(generated.post_incident_recommendations), 'No post-incident recommendations provided.');
              document.getElementById('userAdvisory').textContent = generated.user_advisory || document.getElementById('userAdvisory').textContent;
              loadHistory();
            })
            .catch(error => console.warn('AI report generation failed:', error));
        }
        setTimeout(loadHistory, 500);
      } catch (error) {
        isScanRunning = false;
        setScanInteractionState({ inputDisabled: false, buttonDisabled: false, buttonLabel: 'Scan URL' });
        document.body.classList.remove('status-scanning');
        resultDiv.className = 'result-message error';
        resultDiv.textContent = error.message || 'Analysis failed. Please try again.';
      }
    });

    document.getElementById('registerForm').addEventListener('submit', async (event) => {
      event.preventDefault();
      const form = event.currentTarget;
      const formData = new FormData(form);
      const data = Object.fromEntries(formData);
      const resultDiv = document.getElementById('registerResult');

      try {
        const response = await fetch('../api/register_user.php', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data)
        });
        const result = await parseJsonResponse(response);

        if (result.success) {
          resultDiv.className = 'result-message success';
          resultDiv.textContent = result.message || 'User registered successfully';
          form.reset();
          setTimeout(loadUsers, 500);
        } else {
          resultDiv.className = 'result-message error';
          resultDiv.textContent = result.message || 'Unable to register user.';
        }
      } catch (error) {
        resultDiv.className = 'result-message error';
        resultDiv.textContent = error.message || 'Unable to register user.';
      }
    });

    async function loadUsers() {
      try {
        const response = await fetch('../api/get_users.php');
        const users = await parseJsonResponse(response);
        const tbody = document.getElementById('usersTableBody');

        if (!Array.isArray(users) || users.length === 0) {
          tbody.innerHTML = '<tr><td colspan="8" class="empty-state"><p>No users registered yet</p></td></tr>';
          return;
        }

        tbody.innerHTML = users.map(user => `
          <tr>
            <td>${escapeHtml(user.id)}</td>
            <td>${escapeHtml(user.full_name)}</td>
            <td>${escapeHtml(user.username)}</td>
            <td>${escapeHtml(user.email)}</td>
            <td><span class="badge ${escapeHtml(user.role)}">${escapeHtml(String(user.role).toUpperCase())}</span></td>
            <td><span class="badge ${user.is_active ? 'safe' : 'phishing'}">${escapeHtml(user.account_status || (user.is_active ? 'active' : 'inactive'))}</span></td>
            <td>${user.last_login ? escapeHtml(new Date(user.last_login).toLocaleString()) : 'Never'}</td>
            <td><button class="delete-btn" data-user-delete data-user-id="${Number(user.id)}" data-username="${escapeHtml(user.username)}" title="Delete User">Delete</button></td>
          </tr>
        `).join('');
      } catch (error) {
        document.getElementById('usersTableBody').innerHTML = '<tr><td colspan="8" style="color: red; text-align: center;">Error loading users</td></tr>';
      }
    }

    async function deleteUser(id, username) {
      if (!confirm(`Are you sure you want to delete user "${username}"?\nThis action cannot be undone.`)) return;

      try {
        const response = await fetch('../api/delete_user.php', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id })
        });
        const result = await parseJsonResponse(response);
        if (result.success) {
          alert('User deleted successfully');
          loadUsers();
        } else {
          alert('Error: ' + (result.message || 'Unable to delete user.'));
        }
      } catch (error) {
        alert('Error: ' + error.message);
      }
    }

    async function loadHistory() {
      const filter = document.getElementById('historyFilter').value;
      try {
        const response = await fetch('../api/get_analysis.php?filter=' + encodeURIComponent(filter));
        const history = await parseJsonResponse(response);
        const tbody = document.getElementById('historyTableBody');

        if (!Array.isArray(history) || history.length === 0) {
          tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><p>No analysis history found</p></td></tr>';
          return;
        }

        tbody.innerHTML = history.map(entry => `
          <tr>
            <td>${escapeHtml(entry.id)}</td>
            <td>${escapeHtml(entry.username || '-')}</td>
            <td><a href="${escapeHtml(entry.url)}" target="_blank" style="color: #1d4ed8; text-decoration: none;">${escapeHtml(String(entry.url || '').substring(0, 64))}${String(entry.url || '').length > 64 ? '...' : ''}</a></td>
            <td><span class="badge ${String(entry.display_status || '').toLowerCase().includes('suspicious') ? 'suspicious' : escapeHtml(String(entry.status || '').toLowerCase())}">${escapeHtml(String(entry.display_status || entry.status || '').toUpperCase())}</span></td>
            <td>${(Number(entry.confidence_score || 0) * 100).toFixed(2)}%</td>
            <td>${entry.analyzed_at ? escapeHtml(new Date(entry.analyzed_at).toLocaleString()) : '-'}</td>
            <td>
              <div class="history-action-btns">
                <button class="btn-mini" type="button" data-history-view="${encodeURIComponent(entry.id)}">View</button>
                <a class="btn-mini" style="text-decoration:none;" href="../api/download_report.php?id=${encodeURIComponent(entry.id)}" target="_blank">Download Report</a>
              </div>
            </td>
          </tr>
        `).join('');
      } catch (error) {
        document.getElementById('historyTableBody').innerHTML = '<tr><td colspan="7" style="color: red; text-align: center;">Error loading history</td></tr>';
      }
    }

    function displayScanValue(value, fallback = 'Not Collected') {
      if (value === null || value === undefined || String(value).trim() === '') return fallback;
      return String(value);
    }

    function displayScanNetworkValue(value, type) {
      if (value === null || value === undefined || String(value).trim() === '') {
        return type === 'country' ? 'Private Network' : 'Local Session';
      }
      const normalized = String(value).trim();
      if (['Local/Private', 'localhost', '127.0.0.1', '::1'].includes(normalized)) {
        return type === 'country' ? 'Private Network' : 'Local Session';
      }
      return normalized;
    }

    function formatScanConfidence(value) {
      if (typeof value === 'string' && value.includes('%')) return value;
      const numeric = Number(value || 0);
      const percent = numeric <= 1 ? numeric * 100 : numeric;
      return Number.isFinite(percent) ? percent.toFixed(2) + '%' : 'Not Collected';
    }

    function formatScanDurationValue(value) {
      if (value === null || value === undefined || String(value).trim() === '') return 'Not Collected';
      const numeric = Number(value);
      return Number.isFinite(numeric) ? numeric.toFixed(1) + ' sec' : displayScanValue(value);
    }

    function parseScanFeatures(features) {
      if (features && typeof features === 'object' && !Array.isArray(features)) return features;
      if (typeof features === 'string' && features.trim() !== '') {
        try {
          const parsed = JSON.parse(features);
          return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
        } catch (error) {
          return {};
        }
      }
      return {};
    }

    function normalizeScanList(value) {
      if (Array.isArray(value)) return value.filter(item => item !== null && item !== undefined && String(item).trim() !== '');
      if (typeof value === 'string' && value.trim() !== '') {
        try {
          const parsed = JSON.parse(value);
          return Array.isArray(parsed) ? parsed : [value.trim()];
        } catch (error) {
          return [value.trim()];
        }
      }
      return [];
    }

    function scanFeatureSignal(features, keys) {
      for (const key of keys) {
        if (Object.prototype.hasOwnProperty.call(features, key)) {
          const value = features[key];
          const normalized = String(value).toLowerCase();
          return value === -1 || value === 1 || normalized === 'detected' || normalized === 'yes' || normalized === 'true';
        }
      }
      return false;
    }

    function scanEvidenceBadges(detail) {
      const url = String(detail.url || '');
      const features = parseScanFeatures(detail.features);
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
      if (url.length > 75 || scanFeatureSignal(features, ['LongURL', 'URLURL_Length', 'URL_Length', 'url_length'])) badges.push('Long URL');
      if (brandTerms.some(term => lowerUrl.includes(term))) badges.push('Possible Brand Impersonation');

      if (!badges.length) return '<span>Not Collected</span>';
      return badges.map(label => `<span class="badge suspicious">${escapeHtml(label)}</span>`).join(' ');
    }

    function formatScanList(items) {
      const list = normalizeScanList(items);
      if (!list.length) return '<span>Not Collected</span>';
      return `<ul style="margin:0; padding-left:1.1rem;">${list.map(item => {
        const text = typeof item === 'object' ? (item.action || item.step || item.description || item.name || JSON.stringify(item)) : item;
        return `<li>${escapeHtml(text)}</li>`;
      }).join('')}</ul>`;
    }

    function formatScanMitre(items) {
      const list = normalizeScanList(items);
      if (!list.length) return '<span>Not Collected</span>';
      return list.map(item => {
        const label = typeof item === 'object'
          ? `${item.id || item.technique_id || ''}${((item.id || item.technique_id) && (item.name || item.technique)) ? ' - ' : ''}${item.name || item.technique || item.description || 'Technique'}`
          : item;
        return `<span class="badge">${escapeHtml(label)}</span>`;
      }).join(' ');
    }

    function scanThreatBehavior(detail) {
      const status = String(detail.status || '').toLowerCase();
      const display = String(detail.display_status || detail.display_verdict || '').toLowerCase();
      const evidence = scanEvidenceBadges(detail);
      const bullets = [];
      if (display.includes('suspicious')) bullets.push('Suspicious signals detected, but this URL is not confirmed as phishing.');
      else if (status === 'phishing') bullets.push('Likely credential harvesting or impersonation attempt.');
      if (status === 'suspicious') bullets.push('Suspicious URL indicators require review before user access.');
      if (evidence.includes('Non-HTTPS')) bullets.push('Connection does not use HTTPS.');
      if (evidence.includes('Possible Brand Impersonation')) bullets.push('URL contains terms commonly used in fake login or verification flows.');
      if (evidence.includes('Long URL')) bullets.push('URL length may be used to obscure destination or parameters.');
      if (!bullets.length) bullets.push('No high-risk behavior was collected from available scan details.');
      return bullets;
    }

    function auditModalRow(label, value, isHtml = false) {
      return `<div class="audit-modal-row"><strong>${escapeHtml(label)}</strong>${isHtml ? `<div>${value}</div>` : `<span>${escapeHtml(value)}</span>`}</div>`;
    }

    function openScanHistoryModal(detail) {
      const modal = document.getElementById('scanDetailModal');
      const body = document.getElementById('scanModalBody');
      const status = String(detail.status || '').toUpperCase();
      const displayStatus = String(detail.display_status || detail.display_verdict || status);
      const displayClass = displayStatus.toLowerCase().includes('suspicious') ? 'suspicious' : String(detail.status || '').toLowerCase();
      const checkedUrl = displayScanValue(detail.url);
      const nistActions = normalizeScanList(detail.nist_response).length ? detail.nist_response : detail.incident_response;
      const summary = String(detail.display_status || '').toLowerCase().includes('potentially suspicious')
        ? 'This URL shows suspicious characteristics, but it is not confirmed phishing. Users should verify the website carefully before entering passwords, OTPs, or sensitive information.'
        : displayScanValue(detail.llm_summary);
      const behavior = scanThreatBehavior(detail);

      body.innerHTML = `
        ${auditModalRow('Timestamp', displayScanValue(detail.analyzed_at))}
        ${auditModalRow('User', displayScanValue(detail.username))}
        ${auditModalRow('Checked URL', `<pre title="${escapeHtml(checkedUrl)}">${escapeHtml(checkedUrl)}</pre>`, true)}
        ${auditModalRow('Safety Status', `<span class="badge ${escapeHtml(displayClass)}">${escapeHtml(displayScanValue(displayStatus).toUpperCase())}</span>`, true)}
        ${auditModalRow('System Detection', displayScanValue(status))}
        ${auditModalRow('Risk Level', displayScanValue(detail.risk_level))}
        ${auditModalRow('Confidence Score', formatScanConfidence(detail.confidence_score))}
        ${auditModalRow('Scan Duration', formatScanDurationValue(detail.scan_duration))}
        ${auditModalRow('Detection Engine', displayScanValue(detail.detection_engine))}
        ${auditModalRow('IP Address', displayScanNetworkValue(detail.ip_address, 'ip'))}
        ${auditModalRow('Country', displayScanNetworkValue(detail.country, 'country'))}
        ${auditModalRow('Detection Evidence', scanEvidenceBadges(detail), true)}
        ${auditModalRow('Incident Summary', `
          <strong style="display:block; color:#0f172a; margin-bottom:0.35rem;">Threat Behavior</strong>
          <ul style="margin:0 0 0.6rem; padding-left:1.1rem;">${behavior.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>
          <strong style="display:block; color:#0f172a; margin-bottom:0.35rem;">Detailed Summary</strong>
          <pre>${escapeHtml(summary)}</pre>
        `, true)}
        ${auditModalRow('NIST Actions', formatScanList(nistActions), true)}
        ${auditModalRow('MITRE ATT&CK', formatScanMitre(detail.mitre_attack), true)}
        ${auditModalRow('User Advisory', `<pre>${escapeHtml(displayScanValue(detail.user_advisory))}</pre>`, true)}
      `;
      modal.classList.add('show');
      modal.setAttribute('aria-hidden', 'false');
    }

    function closeScanHistoryModal() {
      const modal = document.getElementById('scanDetailModal');
      modal.classList.remove('show');
      modal.setAttribute('aria-hidden', 'true');
    }

    async function viewScanHistoryDetail(reportId) {
      const response = await fetch('../api/get_report_detail.php?id=' + encodeURIComponent(reportId));
      const detail = await parseJsonResponse(response);
      openScanHistoryModal(detail);
    }

    function populateAuditFilter(selectId, values, currentValue) {
      const select = document.getElementById(selectId);
      if (!select) return;
      select.innerHTML = '<option value="">All</option>' + values.map(value => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join('');
      select.value = currentValue || '';
    }

    async function loadAuditLogs() {
      const params = new URLSearchParams({
        search: document.getElementById('auditSearch').value.trim(),
        activity: document.getElementById('auditActivity').value,
        status: document.getElementById('auditStatus').value,
        date_from: document.getElementById('auditDateFrom').value,
        date_to: document.getElementById('auditDateTo').value,
        division: document.getElementById('auditDivision').value,
        country: document.getElementById('auditCountry').value
      });

      try {
        const response = await fetch('../api/get_audit_logs.php?' + params.toString());
        const result = await parseJsonResponse(response);
        const tbody = document.getElementById('auditTableBody');
        const filters = result.filters || {};
        populateAuditFilter('auditActivity', filters.activities || [], document.getElementById('auditActivity').value);
        populateAuditFilter('auditDivision', filters.divisions || [], document.getElementById('auditDivision').value);
        populateAuditFilter('auditCountry', filters.countries || [], document.getElementById('auditCountry').value);

        const logs = Array.isArray(result.logs) ? result.logs : [];
        auditLogCache = {};
        if (logs.length === 0) {
          tbody.innerHTML = '<tr><td colspan="9" class="empty-state"><p>No audit logs found</p></td></tr>';
          return;
        }

        tbody.innerHTML = logs.map((log, index) => {
          const cacheKey = String(log.id || index);
          auditLogCache[cacheKey] = log;
          return `
          <tr>
            <td class="audit-col-time audit-nowrap" data-label="Timestamp" title="${escapeHtml(log.timestamp || '-')}">${escapeHtml(log.timestamp || '-')}</td>
            <td class="audit-col-user audit-user" data-label="User" title="${escapeHtml(log.username || '-')}">${escapeHtml(log.username || '-')}</td>
            <td class="audit-col-role audit-ellipsis" data-label="Role" title="${escapeHtml(log.role || '-')}">${escapeHtml(log.role || '-')}</td>
            <td class="audit-col-division audit-ellipsis audit-hide-tablet" data-label="Division" title="${escapeHtml(log.division || '-')}">${escapeHtml(log.division || '-')}</td>
            <td class="audit-col-activity audit-ellipsis" data-label="Activity" title="${escapeHtml(auditActivityLabel(log.activity_type))}"><span class="badge">${escapeHtml(auditActivityLabel(log.activity_type))}</span></td>
            <td class="audit-col-ip audit-nowrap" data-label="IP Address" title="${escapeHtml(log.ip_address || '-')}">${escapeHtml(log.ip_address || '-')}</td>
            <td class="audit-col-country audit-ellipsis audit-hide-tablet" data-label="Country" title="${escapeHtml(log.country || '-')}">${escapeHtml(log.country || '-')}</td>
            <td class="audit-col-status" data-label="Status"><span class="badge ${String(log.status).toLowerCase() === 'success' ? 'safe' : 'phishing'}">${escapeHtml(log.status || '-')}</span></td>
            <td class="audit-col-details" data-label="Details"><button class="audit-detail-btn" type="button" data-audit-detail="${escapeHtml(cacheKey)}">View</button></td>
          </tr>
        `;
        }).join('');
      } catch (error) {
        document.getElementById('auditTableBody').innerHTML = '<tr><td colspan="9" style="color: red; text-align: center;">Error loading audit logs</td></tr>';
      }
    }

    function openAuditModal(log) {
      if (!log) return;
      const modal = document.getElementById('auditDetailModal');
      const body = document.getElementById('auditModalBody');
      body.innerHTML = `
        <div class="audit-modal-row"><strong>Timestamp</strong><span>${escapeHtml(log.timestamp || '-')}</span></div>
        <div class="audit-modal-row"><strong>User</strong><span>${escapeHtml(log.username || '-')} (ID: ${escapeHtml(log.user_id || '-')})</span></div>
        <div class="audit-modal-row"><strong>Role</strong><span>${escapeHtml(log.role || '-')}</span></div>
        <div class="audit-modal-row"><strong>Division</strong><span>${escapeHtml(log.division || '-')}</span></div>
        <div class="audit-modal-row"><strong>Activity</strong><span>${escapeHtml(auditActivityLabel(log.activity_type))}</span></div>
        <div class="audit-modal-row"><strong>IP Address</strong><span>${escapeHtml(log.ip_address || '-')}</span></div>
        <div class="audit-modal-row"><strong>Country</strong><span>${escapeHtml(log.country || '-')}</span></div>
        <div class="audit-modal-row"><strong>Status</strong><span>${escapeHtml(log.status || '-')}</span></div>
        <div class="audit-modal-row"><strong>Session ID</strong><span>${escapeHtml(log.session_id || '-')}</span></div>
        <div class="audit-modal-row"><strong>Details</strong><pre>${escapeHtml(log.activity_details || '-')}</pre></div>
      `;
      modal.classList.add('show');
      modal.setAttribute('aria-hidden', 'false');
    }

    function closeAuditModal() {
      const modal = document.getElementById('auditDetailModal');
      modal.classList.remove('show');
      modal.setAttribute('aria-hidden', 'true');
    }

    function resetAuditFilters() {
      ['auditSearch', 'auditActivity', 'auditStatus', 'auditDateFrom', 'auditDateTo', 'auditDivision', 'auditCountry'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
      });
      loadAuditLogs();
    }

    document.getElementById('historyFilter').addEventListener('change', loadHistory);
    document.getElementById('historyRefreshBtn').addEventListener('click', loadHistory);
    document.getElementById('historyTableBody').addEventListener('click', async (event) => {
      const button = event.target.closest('[data-history-view]');
      if (!button) return;
      button.disabled = true;
      const previousText = button.textContent;
      button.textContent = 'Loading...';
      try {
        await viewScanHistoryDetail(button.dataset.historyView);
      } catch (error) {
        alert(error.message || 'Unable to load scan details.');
      } finally {
        button.disabled = false;
        button.textContent = previousText;
      }
    });
    document.getElementById('auditRefreshBtn').addEventListener('click', loadAuditLogs);
    document.getElementById('auditResetBtn').addEventListener('click', resetAuditFilters);
    ['auditSearch', 'auditActivity', 'auditStatus', 'auditDateFrom', 'auditDateTo', 'auditDivision', 'auditCountry'].forEach(id => {
      document.getElementById(id)?.addEventListener('change', loadAuditLogs);
    });
    document.getElementById('auditSearch')?.addEventListener('input', () => {
      clearTimeout(window.auditSearchTimer);
      window.auditSearchTimer = setTimeout(loadAuditLogs, 350);
    });
    document.getElementById('auditTableBody').addEventListener('click', (event) => {
      const button = event.target.closest('[data-audit-detail]');
      if (!button) return;
      openAuditModal(auditLogCache[button.dataset.auditDetail]);
    });
    document.getElementById('auditModalCloseBtn').addEventListener('click', closeAuditModal);
    document.getElementById('auditDetailModal').addEventListener('click', (event) => {
      if (event.target.id === 'auditDetailModal') closeAuditModal();
    });
    document.getElementById('scanModalCloseBtn').addEventListener('click', closeScanHistoryModal);
    document.getElementById('scanDetailModal').addEventListener('click', (event) => {
      if (event.target.id === 'scanDetailModal') closeScanHistoryModal();
    });
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        closeAuditModal();
        closeScanHistoryModal();
      }
    });
    document.getElementById('usersTableBody').addEventListener('click', (event) => {
      const button = event.target.closest('[data-user-delete]');
      if (!button) return;
      deleteUser(Number(button.dataset.userId), button.dataset.username || '');
    });
    document.querySelectorAll('.dashboard-tab-btn').forEach(button => {
      button.addEventListener('click', () => switchDashboardTab(button.dataset.tabTarget));
    });

    document.getElementById('downloadReportBtn').addEventListener('click', () => {
      const label = document.getElementById('downloadReportLabel');
      const button = document.getElementById('downloadReportBtn');
      button.classList.add('is-loading');
      label.textContent = 'Preparing report...';
      setTimeout(() => {
        button.classList.remove('is-loading');
        button.classList.add('is-success');
        label.textContent = 'Report ready';
        setTimeout(() => {
          button.classList.remove('is-success');
          label.textContent = 'Download Report';
        }, 1400);
      }, 700);
    });

    window.addEventListener('load', () => {
      resetAssistant(null);
      loadHistory();
      loadAuditLogs();
    });
  </script>
</body>

</html>
