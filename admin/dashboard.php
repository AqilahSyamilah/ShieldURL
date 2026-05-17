<?php
require_once '../config/db.php';

// Check if admin is logged in
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
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
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Dashboard - ShieldURL</title>
    <style>
        * {
            box-sizing: border-box;
        }
        body {
            margin: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .dashboard {
            background: #f7fafc;
            min-height: 100vh;
        }
        .dashboard header {
            background: white;
            padding: 1rem 2rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .logout-btn {
            background: #fc8181;
            color: white;
            padding: 8px 16px;
            border-radius: 5px;
            text-decoration: none;
        }
        .logout-btn:hover {
            background: #f56565;
        }
        .admin-nav {
            background: #2d3748;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .admin-nav a {
            color: white;
            text-decoration: none;
            padding: 10px 15px;
            margin-right: 10px;
            border-radius: 5px;
            transition: background 0.3s;
        }
        .admin-nav a:hover {
            background: #4a5568;
        }
        .admin-nav a.active {
            background: #667eea;
        }
        .admin-container {
            display: grid;
            grid-template-columns: 300px 1fr;
            gap: 20px;
        }
        .admin-sidebar {
            background: #f7fafc;
            padding: 20px;
            border-radius: 10px;
            height: fit-content;
        }
        .admin-content {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .user-form {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin-top: 20px;
        }
        .form-group {
            margin-bottom: 15px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #4a5568;
            font-weight: 500;
        }
        .form-group input,
        .form-group select {
            width: 100%;
            padding: 10px;
            border: 1px solid #e2e8f0;
            border-radius: 5px;
            font-size: 14px;
        }
        .form-group.full-width {
            grid-column: 1 / -1;
        }
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
        }
        .btn-primary {
            background: #667eea;
            color: white;
        }
        .btn-primary:hover {
            background: #5a67d8;
        }
        .btn-secondary {
            background: #a0aec0;
            color: white;
        }
        .users-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .users-table th,
        .users-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }
        .users-table th {
            background: #f7fafc;
            font-weight: 600;
            color: #4a5568;
        }
        .status-active {
            color: #38a169;
            font-weight: 500;
        }
        .status-inactive {
            color: #e53e3e;
            font-weight: 500;
        }
        .action-buttons {
            display: flex;
            gap: 8px;
        }
        .btn-small {
            padding: 5px 10px;
            font-size: 12px;
            border-radius: 3px;
        }
        .btn-edit {
            background: #4299e1;
            color: white;
        }
        .btn-delete {
            background: #f56565;
            color: white;
        }
    </style>
</head>
<body>
    <div class="dashboard">
        <header>
            <h1>🛡️ Admin Dashboard</h1>
            <div class="user-info">
                <span>Welcome, <strong><?php echo $_SESSION['username']; ?></strong> (Admin)</span>
                <a href="../auth/logout.php" class="logout-btn">Logout</a>
            </div>
        </header>
        
        <nav class="admin-nav">
            <a href="dashboard.php" class="active">📊 Dashboard</a>
            <a href="users.php">👥 Manage Users</a>
            <a href="reports.php">📈 Reports</a>
            <a href="settings.php">⚙️ Settings</a>
        </nav>
        
        <div class="admin-container">
            <!-- Sidebar -->
            <div class="admin-sidebar">
                <h3>Quick Actions</h3>
                <div style="display: flex; flex-direction: column; gap: 10px; margin-top: 15px;">
                    <button onclick="showUserRegistration()" class="btn btn-primary">➕ Add New User</button>
                    <button onclick="showAllUsers()" class="btn btn-secondary">👥 View All Users</button>
                    <button onclick="showStatistics()" class="btn btn-secondary">📊 View Statistics</button>
                    <button onclick="showActivityLog()" class="btn btn-secondary">📝 Activity Log</button>
                </div>
                
                <!-- Quick Stats -->
                <div style="margin-top: 30px; padding: 15px; background: white; border-radius: 8px;">
                    <h4>Quick Stats</h4>
                    <div style="margin-top: 10px;">
                        <p>👥 Total Users: <span id="totalUsers">0</span></p>
                        <p>✅ Active Users: <span id="activeUsers">0</span></p>
                        <p>📊 Total Analyses: <span id="totalAnalyses">0</span></p>
                    </div>
                </div>
            </div>
            
            <!-- Main Content -->
            <div class="admin-content">
                <h2>User Management</h2>
                
                <!-- User Registration Form -->
                <div id="userRegistrationForm" style="display: block;">
                    <h3>Register New User</h3>
                    <form id="registerUserForm" class="user-form">
                        <div class="form-group">
                            <label for="full_name">Full Name *</label>
                            <input type="text" id="full_name" name="full_name" required>
                        </div>
                        
                        <div class="form-group">
                            <label for="email">Email *</label>
                            <input type="email" id="email" name="email" required>
                        </div>
                        
                        <div class="form-group">
                            <label for="phone">Phone Number</label>
                            <input type="tel" id="phone" name="phone">
                        </div>
                        
                        <div class="form-group">
                            <label for="department">Department</label>
                            <select id="department" name="department">
                                <option value="">Select Department</option>
                                <option value="IT">IT Department</option>
                                <option value="Security">Security</option>
                                <option value="HR">Human Resources</option>
                                <option value="Finance">Finance</option>
                                <option value="Marketing">Marketing</option>
                                <option value="Operations">Operations</option>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label for="role">User Role *</label>
                            <select id="role" name="role" required>
                                <option value="user">Regular User</option>
                                <option value="admin">Administrator</option>
                            </select>
                        </div>
                        <div class="form-group full-width">
                            <p style="margin: 0; color: #4a5568;">ShieldURL will generate a temporary password, email it to the user, and require password change plus email code verification at first login.</p>
                        </div>
                        
                        <div class="form-group full-width">
                            <button type="submit" class="btn btn-primary">Register User</button>
                            <button type="button" onclick="clearForm()" class="btn btn-secondary">Clear Form</button>
                        </div>
                    </form>
                    <div id="registrationMessage" style="margin-top: 15px;"></div>
                </div>
                
                <!-- Users List -->
                <div id="usersList" style="display: none; margin-top: 30px;">
                    <h3>All Users</h3>
                    <div id="usersTableContainer">
                        <p>Loading users...</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        async function parseJsonResponse(response) {
            const text = await response.text();
            console.log('Raw response:', text);

            let data = null;
            if (text.trim() !== '') {
                try {
                    data = JSON.parse(text);
                } catch (error) {
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

        // Global variables
        let currentView = 'registration';
        
        // Show/Hide sections
        function showUserRegistration() {
            document.getElementById('userRegistrationForm').style.display = 'block';
            document.getElementById('usersList').style.display = 'none';
            currentView = 'registration';
            document.title = 'Admin - Register User';
        }
        
        function showAllUsers() {
            document.getElementById('userRegistrationForm').style.display = 'none';
            document.getElementById('usersList').style.display = 'block';
            currentView = 'users';
            document.title = 'Admin - Manage Users';
            loadUsers();
        }
        
        // Load statistics
        async function loadStatistics() {
            try {
                const response = await fetch('../api/admin_stats.php');
                const data = await parseJsonResponse(response);
                
                document.getElementById('totalUsers').textContent = data.total_users || 0;
                document.getElementById('activeUsers').textContent = data.active_users || 0;
                document.getElementById('totalAnalyses').textContent = data.total_analyses || 0;
            } catch (error) {
                console.error('Error loading statistics:', error);
            }
        }
        
        // Load users list
        async function loadUsers() {
            try {
                const response = await fetch('../api/get_users.php');
                const data = await parseJsonResponse(response);
                
                if (data.length > 0) {
                    let html = `
                        <table class="users-table">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Full Name</th>
                                    <th>Username</th>
                                    <th>Email</th>
                                    <th>Role</th>
                                    <th>Department</th>
                                    <th>Status</th>
                                    <th>Registered</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                    `;
                    
                    data.forEach(user => {
                        const statusClass = user.is_active ? 'status-active' : 'status-inactive';
                        const statusText = user.is_active ? 'Active' : 'Inactive';
                        const registeredDate = new Date(user.registered_at).toLocaleDateString();
                        
                        html += `
                            <tr>
                                <td>${user.id}</td>
                                <td>${user.full_name || '-'}</td>
                                <td>${user.username}</td>
                                <td>${user.email}</td>
                                <td>${user.role}</td>
                                <td>${user.department || '-'}</td>
                                <td class="${statusClass}">${user.account_status || statusText}</td>
                                <td>${registeredDate}</td>
                                <td>
                                    <div class="action-buttons">
                                        <button onclick="editUser(${user.id})" class="btn-small btn-edit">Edit</button>
                                        <button onclick="deleteUser(${user.id})" class="btn-small btn-delete">Delete</button>
                                    </div>
                                </td>
                            </tr>
                        `;
                    });
                    
                    html += `</tbody></table>`;
                    document.getElementById('usersTableContainer').innerHTML = html;
                } else {
                    document.getElementById('usersTableContainer').innerHTML = '<p>No users found.</p>';
                }
            } catch (error) {
                console.error('Error loading users:', error);
                document.getElementById('usersTableContainer').innerHTML = '<p>Error loading users. Please try again.</p>';
            }
        }
        
        // Handle user registration
        document.getElementById('registerUserForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            // Get form data
            const formData = {
                full_name: document.getElementById('full_name').value,
                email: document.getElementById('email').value,
                phone: document.getElementById('phone').value,
                department: document.getElementById('department').value,
                role: document.getElementById('role').value
            };
            
            // Show loading
            showMessage('Registering user...', 'loading');
            
            try {
                const response = await fetch('../api/register_user.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(formData)
                });
                
                const result = await parseJsonResponse(response);
                
                if (result.success) {
                    showMessage(result.message, 'success');
                    clearForm();
                    loadStatistics(); // Refresh stats
                    
                    // If viewing users list, refresh it
                    if (currentView === 'users') {
                        loadUsers();
                    }
                } else {
                    showMessage(result.message || 'Registration failed!', 'error');
                }
            } catch (error) {
                console.error('Error registering user:', error);
                showMessage('Server error. Please try again.', 'error');
            }
        });
        
        // Helper functions
        function showMessage(message, type) {
            const messageDiv = document.getElementById('registrationMessage');
            messageDiv.innerHTML = `
                <div style="padding: 10px; border-radius: 5px; 
                    background: ${type === 'error' ? '#fed7d7' : type === 'success' ? '#c6f6d5' : '#e2e8f0'}; 
                    color: ${type === 'error' ? '#742a2a' : type === 'success' ? '#22543d' : '#4a5568'};">
                    ${message}
                </div>
            `;
            
            // Auto-hide success messages after 5 seconds
            if (type === 'success') {
                setTimeout(() => {
                    messageDiv.innerHTML = '';
                }, 5000);
            }
        }
        
        function clearForm() {
            document.getElementById('registerUserForm').reset();
            document.getElementById('registrationMessage').innerHTML = '';
        }
        
        function editUser(userId) {
            alert(`Edit user ${userId} - Feature coming soon!`);
        }
        
        function deleteUser(userId) {
            if (confirm('Are you sure you want to delete this user?')) {
                alert(`Delete user ${userId} - Feature coming soon!`);
            }
        }
        
        // Load statistics on page load
        document.addEventListener('DOMContentLoaded', loadStatistics);
    </script>
</body>
</html>
