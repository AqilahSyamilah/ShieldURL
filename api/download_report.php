<?php
require_once '../config/db.php';

if (!isset($_SESSION['user_id'])) {
    session_start();
}

if (!isset($_SESSION['user_id']) || !isset($_GET['id'])) {
    die("Access denied");
}

$db = new Database();
$conn = $db->getConnection();

// Fetch analysis
$stmt = $conn->prepare("SELECT * FROM url_logs WHERE id = ? AND user_id = ?");
$stmt->execute([$_GET['id'], $_SESSION['user_id']]);
$report = $stmt->fetch();

if (!$report) {
    die("Report not found");
}

$features = json_decode($report['features'], true);
$mitre = json_decode($report['mitre_attack_json'], true);
$ir_steps = json_decode($report['incident_response_text'], true); // Stored as JSON array in text column
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>ShieldURL Report #<?php echo $report['id']; ?></title>
    <style>
        body {
            font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
            color: #333;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 40px;
        }

        .header {
            border-bottom: 2px solid #eee;
            padding-bottom: 20px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #667eea;
        }

        .meta {
            color: #666;
            font-size: 0.9em;
            text-align: right;
        }

        h1 {
            margin: 0;
            font-size: 28px;
        }

        h2 {
            border-left: 4px solid #667eea;
            padding-left: 10px;
            color: #444;
            margin-top: 30px;
        }

        .status-box {
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            text-align: center;
        }

        .safe {
            background: #f0fff4;
            color: #22543d;
            border: 1px solid #c6f6d5;
        }

        .phishing {
            background: #fff5f5;
            color: #c53030;
            border: 1px solid #feb2b2;
        }

        .suspicious {
            background: #fffaf0;
            color: #9c4221;
            border: 1px solid #fbd38d;
        }

        .status-title {
            font-size: 24px;
            font-weight: bold;
            text-transform: uppercase;
        }

        .grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }

        .field {
            margin-bottom: 10px;
        }

        .label {
            font-weight: bold;
            color: #666;
            display: block;
            font-size: 0.85em;
            text-transform: uppercase;
        }

        .value {
            background: #f7fafc;
            padding: 10px;
            border-radius: 4px;
            word-break: break-all;
        }

        ul {
            margin-top: 5px;
            padding-left: 20px;
        }

        li {
            margin-bottom: 5px;
        }

        .mitre-tag {
            display: inline-block;
            background: #e2e8f0;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            margin-right: 5px;
        }

        .btn-print {
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            float: right;
        }

        @media print {
            .btn-print {
                display: none;
            }

            body {
                padding: 0;
            }
        }
    </style>
</head>

<body>
    <button class="btn-print" onclick="window.print()">Print / Save PDF</button>

    <div class="header">
        <div class="logo">ShieldURL Incident Report</div>
        <div class="meta">
            Case ID: #<?php echo str_pad($report['id'], 6, '0', STR_PAD_LEFT); ?><br>
            Date: <?php echo $report['analyzed_at']; ?>
        </div>
    </div>

    <div class="status-box <?php echo $report['status']; ?>">
        <div class="status-title"><?php echo $report['status']; ?></div>
        <div>Risk Level: <strong><?php echo strtoupper($report['risk_level'] ?? 'N/A'); ?></strong> | Confidence:
            <strong><?php echo number_format($report['confidence_score'] * 100, 1); ?>%</strong>
        </div>
    </div>

    <div class="field">
        <span class="label">Analyzed URL</span>
        <div class="value"><?php echo htmlspecialchars($report['url']); ?></div>
    </div>

    <div class="field">
        <span class="label">Executive Summary</span>
        <div class="value" style="background: #fff; border-left: 4px solid #ddd; padding-left: 15px;">
            <?php echo nl2br(htmlspecialchars($report['llm_summary'] ?: "No summary available.")); ?>
        </div>
    </div>

    <h2>Incident Response Plan</h2>
    <?php if (!empty($ir_steps)): ?>
        <ul>
            <?php foreach ($ir_steps as $step): ?>
                <li><?php echo htmlspecialchars($step); ?></li>
            <?php endforeach; ?>
        </ul>
    <?php else: ?>
        <p>No specific actions required.</p>
    <?php endif; ?>

    <h2>MITRE ATT&CK Mapping</h2>
    <?php if (!empty($mitre)): ?>
        <div>
            <?php foreach ($mitre as $m): ?>
                <div style="margin-bottom: 10px;">
                    <span class="mitre-tag"><?php echo htmlspecialchars($m['id']); ?></span>
                    <strong><?php echo htmlspecialchars($m['name']); ?></strong>
                </div>
            <?php endforeach; ?>
        </div>
    <?php else: ?>
        <p>No techniques mapped.</p>
    <?php endif; ?>

    <h2>Technical Features Identified</h2>
    <div class="grid">
        <?php
        if ($features) {
            foreach ($features as $k => $v) {
                if ($v === -1) { // Only show suspicious (-1) or significant features
                    $label = preg_replace('/(?<!\ )[A-Z]/', ' $0', $k);
                    echo "<div class='field'><span class='label'>$label</span><div class='value'>Detected</div></div>";
                }
            }
        }
        ?>
    </div>

    <div
        style="margin-top: 50px; border-top: 1px solid #ddd; padding-top: 20px; font-size: 0.8em; color: #999; text-align: center;">
        Generated by ShieldURL Automated Response System
    </div>
</body>

</html>