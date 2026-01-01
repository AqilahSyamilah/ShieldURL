<?php
require_once 'config/db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: auth/login.php");
    exit();
}

$db = new Database();
$conn = $db->getConnection();

// Get user's statistics
$stmt = $conn->prepare("SELECT COUNT(*) as total_checks FROM url_logs WHERE user_id=?");
$stmt->execute([$_SESSION['user_id']]);
$total_checks = $stmt->fetch()['total_checks'];

$stmt = $conn->prepare("SELECT COUNT(*) as phishing_count FROM url_logs WHERE user_id=? AND status='phishing'");
$stmt->execute([$_SESSION['user_id']]);
$phishing_count = $stmt->fetch()['phishing_count'];

$stmt = $conn->prepare("SELECT COUNT(*) as safe_count FROM url_logs WHERE user_id=? AND status='safe'");
$stmt->execute([$_SESSION['user_id']]);
$safe_count = $stmt->fetch()['safe_count'];
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShieldURL - URL Checker</title>
    <link rel="stylesheet" href="asset/style.css">
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

        .user-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .user-header h1 {
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

        .container {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 1rem;
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
            border: 2px solid #e0e0e0;
            border-radius: 5px;
            font-size: 1rem;
            font-family: inherit;
            transition: all 0.3s;
        }

        .form-group input:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .form-row {
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 1rem;
        }

        .btn-check {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 0.8rem 2rem;
            border: none;
            border-radius: 5px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            height: fit-content;
        }

        .btn-check:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }

        .btn-check:active {
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

        .result-message.loading {
            background: #bee3f8;
            color: #2c5282;
            border-left: 4px solid #3182ce;
            display: block;
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

        @media (max-width: 768px) {
            .user-header {
                flex-direction: column;
                gap: 1rem;
                text-align: center;
            }

            .user-header h1 {
                font-size: 1.5rem;
            }

            .form-row {
                grid-template-columns: 1fr;
            }

            .stats-grid {
                grid-template-columns: 1fr;
            }

            .card {
                padding: 1.5rem;
            }
        }
    </style>
</head>

<body>
    <div class="user-header">
        <h1>ShieldURL</h1>
        <div class="user-info">
            <span>Welcome, <strong><?php echo htmlspecialchars($_SESSION['username']); ?></strong></span>
            <a class="logout-btn" href="auth/logout.php">Logout</a>
        </div>
    </div>

    <div class="container">
        <!-- Statistics -->
        <div class="stats-grid">
            <div class="stat-card">
                <h3>URLs Checked</h3>
                <div class="number"><?php echo $total_checks; ?></div>
            </div>
            <div class="stat-card">
                <h3>Safe URLs</h3>
                <div class="number" style="color: #48bb78;"><?php echo $safe_count; ?></div>
            </div>
            <div class="stat-card">
                <h3>Phishing</h3>
                <div class="number" style="color: #f56565;"><?php echo $phishing_count; ?></div>
            </div>
        </div>

        <!-- Check URL -->
        <div class="card">
            <h2>Check URL Safety</h2>
            <form id="checkUrlForm" class="check-form">
                <div class="form-group">
                    <label for="url">Enter URL to Check</label>
                    <div class="form-row">
                        <input type="url" id="url" name="url" placeholder="https://example.com" required>
                        <button type="submit" class="btn-check">Analyze</button>
                    </div>
                </div>
                <div id="checkResult" class="result-message"></div>
            </form>

            <!-- Analysis Result -->
            <div id="analysisResult" class="analysis-result">
                <div class="result-field">
                    <label>URL Status</label>
                    <div class="result-value">
                        <span id="statusBadge" class="badge"></span>
                    </div>
                </div>

                <div class="result-field">
                    <label>Checked URL</label>
                    <div class="result-value">
                        <a id="resultUrl" href="#" target="_blank" style="word-break: break-all;">Loading...</a>
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
                        <a id="downloadReportBtn" href="#" target="_blank" class="btn-check"
                            style="background: #2d3748; padding: 0.6rem 1.2rem; font-size: 0.9rem;">Download
                            Report</a>
                    </div>
                </div>
            </div>
        </div>

        <!-- History -->
        <div class="card">
            <h2>Your Check History</h2>
            <div style="display: grid; grid-template-columns: 1fr auto; gap: 1rem; margin-bottom: 1rem;">
                <div class="form-group">
                    <label>Filter by Status</label>
                    <select id="historyFilter"
                        style="padding: 0.8rem; border: 2px solid #e0e0e0; border-radius: 5px; font-size: 1rem;">
                        <option value="">All</option>
                        <option value="safe">Safe</option>
                        <option value="phishing">Phishing</option>
                        <option value="suspicious">Suspicious</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>&nbsp;</label>
                    <button class="btn-check" onclick="loadHistory()" style="width: 100%;">Refresh</button>
                </div>
            </div>

            <div class="table-wrapper">
                <table class="history-table">
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>Status</th>
                            <th>Confidence</th>
                            <th>Checked At</th>
                        </tr>
                    </thead>
                    <tbody id="historyTableBody">
                        <tr>
                            <td colspan="4" class="empty-state">
                                <p>Loading your history...</p>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        // Check URL
        document.getElementById('checkUrlForm').addEventListener('submit', async (e) => {
            e.preventDefault();

            const url = document.getElementById('url').value;
            const resultDiv = document.getElementById('checkResult');

            resultDiv.className = 'result-message loading';
            resultDiv.textContent = 'Analyzing URL...';

            try {
                const response = await fetch('api/analyze.php', {
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
                    document.getElementById('resultUrl').href = result.url;
                    document.getElementById('resultUrl').textContent = result.url;

                    const confidence = result.confidence_score * 100;
                    document.getElementById('confidenceScore').textContent = confidence.toFixed(2) + '%';
                    document.getElementById('confidenceFill').style.width = confidence + '%';

                    document.getElementById('analysisDetails').textContent = JSON.stringify(result.features, null, 2); // Show features for now as "details"
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
                    if (result.report_id) {
                        document.getElementById('downloadReportBtn').href = 'api/download_report.php?id=' + result.report_id;
                        document.getElementById('downloadReportBtn').style.display = 'inline-block';
                    } else {
                        document.getElementById('downloadReportBtn').style.display = 'none';
                    }

                    const statusBadge = document.getElementById('statusBadge');
                    statusBadge.className = 'badge ' + result.status;
                    statusBadge.textContent = result.status.toUpperCase();

                    document.getElementById('analysisResult').classList.add('show');
                    document.getElementById('url').value = '';

                    // Reload history
                    setTimeout(() => loadHistory(), 500);
                } else {
                    resultDiv.className = 'result-message error';
                    // Show a friendly fallback if backend didn't return a message
                    resultDiv.textContent = 'Error: ' + (result.message || JSON.stringify(result));
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
                const response = await fetch('api/get_analysis.php?filter=' + filter);
                const history = await response.json();
                const tbody = document.getElementById('historyTableBody');

                if (!Array.isArray(history) || history.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" class="empty-state"><p>No URLs checked yet</p></td></tr>';
                    return;
                }

                tbody.innerHTML = history.map(entry => `
                    <tr>
                        <td><a href="${entry.url}" target="_blank">${entry.url.substring(0, 60)}${entry.url.length > 60 ? '...' : ''}</a></td>
                        <td><span class="badge ${entry.status}">${entry.status.toUpperCase()}</span></td>
                        <td>${(entry.confidence_score * 100).toFixed(2)}%</td>
                        <td>${new Date(entry.analyzed_at).toLocaleString()}</td>
                    </tr>
                `).join('');
            } catch (error) {
                console.error('Error loading history:', error);
                document.getElementById('historyTableBody').innerHTML = '<tr><td colspan="4" style="color: red; text-align: center;">Error loading history</td></tr>';
            }
        }

        // Add filter listener
        document.getElementById('historyFilter').addEventListener('change', loadHistory);

        // Load initial data
        window.addEventListener('load', () => {
            loadHistory();
        });
    </script>
</body>

</html>
});

const data = await res.json();
document.getElementById("result").textContent =
JSON.stringify(data, null, 2);
});
</script>

</body>

</html>