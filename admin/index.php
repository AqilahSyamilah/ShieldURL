<?php
require_once '../config/db.php';

if (!isset($_SESSION['user_id']) || ($_SESSION['role'] ?? '') !== 'admin') {
  header("Location: ../auth/login.php");
  exit();
}

$db = new Database();
$conn = $db->getConnection();

// Get statistics
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
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: #f0f4f8;
      color: #333;
    }

    .admin-header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 2rem;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .admin-header h1 {
      font-size: 2rem;
      font-weight: 700;
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

    .tab-container {
      max-width: 1400px;
      margin: 2rem auto;
      padding: 0 1rem;
    }

    .tab-buttons {
      display: flex;
      gap: 1rem;
      margin-bottom: 2rem;
      border-bottom: 2px solid #ddd;
      overflow-x: auto;
    }

    .tab-btn {
      padding: 1rem 2rem;
      background: none;
      border: none;
      cursor: pointer;
      font-size: 1rem;
      font-weight: 600;
      color: #666;
      border-bottom: 3px solid transparent;
      transition: all 0.3s;
      white-space: nowrap;
    }

    .tab-btn:hover {
      color: #667eea;
    }

    .tab-btn.active {
      color: #667eea;
      border-bottom-color: #667eea;
    }

    .tab-content {
      display: none;
      animation: fadeIn 0.3s ease-in;
    }

    .tab-content.active {
      display: block;
    }

    @keyframes fadeIn {
      from {
        opacity: 0;
        transform: translateY(10px);
      }

      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 1.5rem;
      margin-bottom: 2rem;
    }

    .stat-card {
      background: white;
      padding: 2rem;
      border-radius: 10px;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
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
      color: #667eea;
    }

    .card {
      background: white;
      padding: 2rem;
      border-radius: 10px;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
      margin-bottom: 2rem;
    }

    .card h2 {
      margin-bottom: 1.5rem;
      color: #333;
      font-size: 1.5rem;
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

    .form-group textarea {
      resize: vertical;
      min-height: 100px;
    }

    .form-group input:focus,
    .form-group select:focus,
    .form-group textarea:focus {
      outline: none;
      border-color: #667eea;
      box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }

    .form-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1rem;
    }

    .btn-submit {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 0.8rem 2rem;
      border: none;
      border-radius: 5px;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s;
    }

    .btn-submit:hover {
      transform: translateY(-2px);
      box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
    }

    .btn-submit:active {
      transform: translateY(0);
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

    table th {
      padding: 1rem;
      text-align: left;
      font-weight: 600;
      color: #333;
    }

    table td {
      padding: 1rem;
      border-bottom: 1px solid #e2e8f0;
    }

    table tbody tr:hover {
      background: #f9fafb;
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

    .empty-state {
      text-align: center;
      padding: 3rem;
      color: #999;
    }

    .empty-state p {
      font-size: 1.1rem;
      margin-bottom: 1rem;
    }

    @media (max-width: 768px) {
      .admin-header {
        flex-direction: column;
        gap: 1rem;
        text-align: center;
      }

      .form-row {
        grid-template-columns: 1fr;
      }

      .tab-buttons {
        flex-wrap: nowrap;
        overflow-x: auto;
      }

      .tab-btn {
        padding: 0.8rem 1rem;
        font-size: 0.9rem;
      }

      .stats-grid {
        grid-template-columns: 1fr;
      }

      .stats-grid {
        grid-template-columns: 1fr;
      }
    }

    .delete-btn {
      background: #fed7d7;
      color: #742a2a;
      border: 1px solid #f56565;
      padding: 0.3rem 0.6rem;
      border-radius: 4px;
      cursor: pointer;
      transition: all 0.2s;
    }

    .delete-btn:hover {
      background: #f56565;
      color: white;
    }


    .analysis-result {
      background: white;
      padding: 2rem;
      border-radius: 10px;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
      margin-top: 2rem;
      display: none;
    }

    .analysis-result.show {
      display: block;
      animation: slideDown 0.3s ease-in;
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

    .result-field {
      margin-bottom: 1.5rem;
    }

    .result-field label {
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
  </style>
</head>

<body>
  <div class="admin-header">
    <h1>ShieldURL Admin Dashboard</h1>
    <div class="user-info">
      <span>Welcome, <strong><?php echo htmlspecialchars($_SESSION['username']); ?></strong></span>
      <a class="logout-btn" href="../auth/logout.php">Logout</a>
    </div>
  </div>

  <div class="tab-container">
    <!-- Statistics -->
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

    <!-- Tab Navigation -->
    <div class="tab-buttons">
      <button class="tab-btn active" onclick="switchTab('registration')">User Registration</button>
      <button class="tab-btn" onclick="switchTab('check-url')">Check URL</button>
      <button class="tab-btn" onclick="switchTab('history')">History</button>
    </div>

    <!-- Tab 1: User Registration -->
    <div id="registration" class="tab-content active">
      <div class="card">
        <h2>Register New User</h2>
        <form id="registerForm">
          <div class="form-row">
            <div class="form-group">
              <label for="full_name">Full Name *</label>
              <input type="text" id="full_name" name="full_name" required>
            </div>
            <div class="form-group">
              <label for="username">Username *</label>
              <input type="text" id="username" name="username" required>
            </div>
          </div>

          <div class="form-row">
            <div class="form-group">
              <label for="email">Email *</label>
              <input type="email" id="email" name="email" required>
            </div>
            <div class="form-group">
              <label for="password">Password *</label>
              <input type="password" id="password" name="password" required>
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

          <button type="submit" class="btn-submit">Register User</button>
          <div id="registerResult" class="result-message"></div>
        </form>
      </div>

      <!-- Registered Users List -->
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
                <td colspan="7" style="text-align: center; color: #999;">Loading...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Tab 2: Check URL -->
    <div id="check-url" class="tab-content">
      <div class="card">
        <h2>Check URL Safety</h2>
        <form id="checkUrlForm">
          <div class="form-group">
            <label for="url">Enter URL to Check *</label>
            <input type="url" id="url" name="url" placeholder="https://example.com" required>
          </div>
          <button type="submit" class="btn-submit">Analyze URL</button>
          <div id="urlResult" class="result-message"></div>
        </form>

        <div id="urlAnalysisResult" class="analysis-result">
          <div class="result-field">
            <label>URL Status</label>
            <div class="result-value">
              <span id="statusBadge" class="badge"></span>
            </div>
          </div>

          <div class="result-field">
            <label>Checked URL</label>
            <div class="result-value">
              <a id="analyzedUrl" href="#" target="_blank" style="word-break: break-all;">Loading...</a>
            </div>
          </div>

          <div class="result-field">
            <label>Confidence Score</label>
            <div class="result-value" id="confidenceScore"
              style="font-size: 1.5rem; color: #667eea; font-weight: bold;">0%</div>
            <div class="confidence-bar">
              <div id="confidenceFill" class="confidence-fill" style="width: 0%"></div>
            </div>
          </div>

          <div class="result-field">
            <label>Executive Summary</label>
            <div class="result-value" id="llmSummary"
              style="background: #f0f4f8; padding: 1rem; border-radius: 5px; border-left: 4px solid #667eea;">
              -</div>
          </div>

          <div class="result-field">
            <label>Recommended Actions</label>
            <ul id="irSteps" style="padding-left: 20px; line-height: 1.6;"></ul>
          </div>

          <div class="result-field">
            <label>MITRE ATT&CK Tags</label>
            <div id="mitreTags" style="display: flex; gap: 10px; flex-wrap: wrap;"></div>
          </div>

          <div class="result-field">
            <label>Analysis Details (Technical)</label>
            <div class="result-value" id="analysisDetails"
              style="background: #f9fafb; padding: 1rem; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word;">
              Loading...</div>
          </div>

          <div class="result-field" style="display: flex; justify-content: space-between; align-items: center;">
            <div>
              <label>Analyzed At</label>
              <div class="result-value" id="analyzedTime">-</div>
            </div>
            <div>
              <a id="downloadReportBtn" href="#" target="_blank" class="btn-submit"
                style="background: #2d3748; padding: 0.6rem 1.2rem; font-size: 0.9rem;">Download
                Report</a>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Tab 3: History -->
    <div id="history" class="tab-content">
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
            <button class="btn-submit" onclick="loadHistory()">🔄 Refresh</button>
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
              </tr>
            </thead>
            <tbody id="historyTableBody">
              <tr>
                <td colspan="6" style="text-align: center; color: #999;">Loading...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <script>
    // Tab Switching
    function switchTab(tabName) {
      // Hide all tabs
      document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
      });

      // Remove active class from all buttons
      document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
      });

      // Show selected tab
      document.getElementById(tabName).classList.add('active');

      // Add active class to clicked button
      event.target.classList.add('active');

      // Load data based on tab
      if (tabName === 'registration') {
        loadUsers();
      } else if (tabName === 'history') {
        loadHistory();
      }
    }

    // Register User
    document.getElementById('registerForm').addEventListener('submit', async (e) => {
      e.preventDefault();

      const formData = new FormData(document.getElementById('registerForm'));
      const data = Object.fromEntries(formData);

      try {
        const response = await fetch('../api/register_user.php', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(data)
        });

        const result = await response.json();
        const resultDiv = document.getElementById('registerResult');

        if (result.success) {
          resultDiv.className = 'result-message success';
          resultDiv.textContent = result.message;
          document.getElementById('registerForm').reset();
          setTimeout(() => loadUsers(), 1000);
        } else {
          resultDiv.className = 'result-message error';
          resultDiv.textContent = (result.message || JSON.stringify(result));
        }
      } catch (error) {
        document.getElementById('registerResult').className = 'result-message error';
        document.getElementById('registerResult').textContent = 'Error: ' + error.message;
      }
    });

    // Load Users
    async function loadUsers() {
      try {
        const response = await fetch('../api/get_users.php');
        const users = await response.json();
        const tbody = document.getElementById('usersTableBody');

        if (users.length === 0) {
          tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><p>No users registered yet</p></td></tr>';
          return;
        }

        tbody.innerHTML = users.map(user => `
          <tr>
            <td>${user.id}</td>
            <td>${user.full_name}</td>
            <td>${user.username}</td>
            <td>${user.email}</td>
            <td><span class="badge ${user.role}">${user.role.toUpperCase()}</span></td>
            <td><span class="badge ${user.is_active ? 'safe' : 'phishing'}">${user.is_active ? 'Active' : 'Inactive'}</span></td>
            <td>${user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}</td>
            <td>
              <button class="delete-btn" onclick="deleteUser(${user.id}, '${user.username}')" title="Delete User">🗑️</button>
            </td>
          </tr>
        `).join('');
      } catch (error) {
        console.error('Error loading users:', error);
        document.getElementById('usersTableBody').innerHTML = '<tr><td colspan="7" style="color: red; text-align: center;">Error loading users</td></tr>';
      }
    }

    // Delete User
    async function deleteUser(id, username) {
      if (!confirm(`Are you sure you want to delete user "${username}"?\nThis action cannot be undone.`)) {
        return;
      }

      try {
        const response = await fetch('../api/delete_user.php', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id })
        });

        const result = await response.json();

        if (result.success) {
          alert('User deleted successfully');
          loadUsers(); // Refresh list
        } else {
          alert('Error: ' + result.message);
        }
      } catch (error) {
        alert('Error: ' + error.message);
      }
    }

    // Check URL
    document.getElementById('checkUrlForm').addEventListener('submit', async (e) => {
      e.preventDefault();

      const url = document.getElementById('url').value;
      const resultDiv = document.getElementById('urlResult');

      resultDiv.className = 'result-message';
      resultDiv.textContent = 'Analyzing URL...';

      try {
        const response = await fetch('../api/analyze.php', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ url })
        });

        let result;
        try {
          result = await response.json();
        } catch (e) {
          const text = await response.text();
          result = { success: false, message: 'Server returned non-JSON response', raw: text };
        }

        if (result.success) {
          resultDiv.className = 'result-message success';
          resultDiv.textContent = 'Analysis complete!';

          // Update result display
          document.getElementById('analyzedUrl').href = result.url;
          document.getElementById('analyzedUrl').textContent = result.url;

          const confidence = result.confidence_score * 100;
          document.getElementById('confidenceScore').textContent = confidence.toFixed(2) + '%';
          document.getElementById('confidenceFill').style.width = confidence + '%';

          document.getElementById('analysisDetails').textContent = JSON.stringify(result.features, null, 2);
          document.getElementById('analyzedTime').textContent = new Date().toLocaleString();

          // New Fields
          document.getElementById('llmSummary').textContent = result.llm_summary || "No summary available.";

          const irContainer = document.getElementById('irSteps');
          irContainer.innerHTML = '';
          if (result.incident_response && Array.isArray(result.incident_response)) {
            result.incident_response.forEach(step => {
              const li = document.createElement('li');
              li.textContent = step;
              irContainer.appendChild(li);
            });
          }

          const mitreContainer = document.getElementById('mitreTags');
          mitreContainer.innerHTML = '';
          if (result.mitre_techniques && Array.isArray(result.mitre_techniques)) {
            result.mitre_techniques.forEach(tech => {
              const span = document.createElement('span');
              span.className = 'badge';
              span.style.background = '#e2e8f0';
              span.style.color = '#4a5568';
              span.style.marginRight = '5px';
              span.textContent = `${tech.id}: ${tech.name}`;
              mitreContainer.appendChild(span);
            });
          }

          if (result.report_id) {
            document.getElementById('downloadReportBtn').href = '../api/download_report.php?id=' + result.report_id;
            document.getElementById('downloadReportBtn').style.display = 'inline-block';
          } else {
            document.getElementById('downloadReportBtn').style.display = 'none';
          }

          const statusBadge = document.getElementById('statusBadge');
          statusBadge.className = 'badge ' + result.status;
          statusBadge.textContent = result.status.toUpperCase();

          document.getElementById('urlAnalysisResult').classList.add('show');
          document.getElementById('urlAnalysisResult').style.display = 'block';
        } else {
          resultDiv.className = 'result-message error';
          resultDiv.textContent = result.message;
        }
      } catch (error) {
        resultDiv.className = 'result-message error';
        resultDiv.textContent = 'Error: ' + error.message;
      }
    });

    // Load History
    async function loadHistory() {
      const filter = document.getElementById('historyFilter').value;

      try {
        const response = await fetch('../api/get_analysis.php?filter=' + filter);
        const history = await response.json();
        const tbody = document.getElementById('historyTableBody');

        if (!Array.isArray(history) || history.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" class="empty-state"><p>No analysis history found</p></td></tr>';
          return;
        }

        tbody.innerHTML = history.map(entry => `
          <tr>
            <td>${entry.id}</td>
            <td>${entry.username}</td>
            <td><a href="${entry.url}" target="_blank" style="color: #667eea; text-decoration: none;">${entry.url.substring(0, 50)}...</a></td>
            <td><span class="badge ${entry.status}">${entry.status.toUpperCase()}</span></td>
            <td>${(entry.confidence_score * 100).toFixed(2)}%</td>
            <td>${new Date(entry.analyzed_at).toLocaleString()}</td>
          </tr>
        `).join('');
      } catch (error) {
        console.error('Error loading history:', error);
        document.getElementById('historyTableBody').innerHTML = '<tr><td colspan="6" style="color: red; text-align: center;">Error loading history</td></tr>';
      }
    }

    // Load initial data
    window.addEventListener('load', () => {
      loadUsers();
    });
  </script>
</body>

</html>