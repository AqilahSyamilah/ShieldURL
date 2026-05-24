<?php
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

require_once '../config/db.php';
require_once '../shared/audit.php';
require_once '../shared/verdict_report.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id']) || !isset($_GET['id'])) {
    http_response_code(403);
    exit('Access denied');
}

function h($value)
{
    return htmlspecialchars((string)($value ?? ''), ENT_QUOTES, 'UTF-8');
}

function safe_decode($value, $fallback = [])
{
    if ($value === null || $value === '') {
        return $fallback;
    }
    $decoded = json_decode($value, true);
    return json_last_error() === JSON_ERROR_NONE ? $decoded : $fallback;
}

function normalize_list($value)
{
    if ($value === null || $value === '') {
        return [];
    }
    if (is_string($value)) {
        $decoded = json_decode($value, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            return normalize_list($decoded);
        }
        return array_values(array_filter(array_map('trim', preg_split('/\r\n|\r|\n|;/', $value))));
    }
    if (!is_array($value)) {
        return [(string)$value];
    }
    $out = [];
    foreach ($value as $item) {
        if (is_array($item)) {
            $out[] = $item['action'] ?? $item['step'] ?? $item['description'] ?? $item['name'] ?? json_encode($item);
        } elseif ($item !== null && $item !== '') {
            $out[] = (string)$item;
        }
    }
    return array_values(array_filter($out));
}

function feature_value($features, $keys, $fallback = '')
{
    foreach ($keys as $key) {
        if (is_array($features) && array_key_exists($key, $features)) {
            $value = $features[$key];
            if (is_bool($value)) {
                return $value ? 'Yes' : 'No';
            }
            if ($value === -1) {
                return 'Detected';
            }
            if ($value === 1) {
                return 'Clean';
            }
            if ($value === 0) {
                return 'Neutral';
            }
            return (string)$value;
        }
    }
    return $fallback;
}

function feature_label($key)
{
    $label = str_replace(['_', '-'], ' ', (string)$key);
    $label = preg_replace('/(?<!^)([A-Z])/', ' $1', $label);
    return ucwords(trim($label));
}

function display_feature_value($value)
{
    if (is_bool($value)) {
        return $value ? 'Yes' : 'No';
    }
    if ($value === null || $value === '') {
        return 'N/A';
    }
    if (is_array($value)) {
        return json_encode($value);
    }
    if ($value === -1) {
        return 'Suspicious';
    }
    if ($value === 1) {
        return 'Clean';
    }
    if ($value === 0) {
        return 'Neutral';
    }
    return (string)$value;
}

function severity_from($status, $riskLevel, $confidence)
{
    $status = strtolower((string)$status);
    $risk = strtolower((string)$riskLevel);
    if ($status === 'phishing' && ($confidence >= 0.85 || $risk === 'high')) {
        return 'Critical';
    }
    if ($status === 'phishing') {
        return 'High';
    }
    if ($status === 'suspicious' || $risk === 'medium') {
        return 'Medium';
    }
    return 'Low';
}

function status_icon($status)
{
    $status = strtolower((string)$status);
    if ($status === 'phishing') {
        return '!';
    }
    if ($status === 'suspicious') {
        return '?';
    }
    return '✓';
}

function suspicious_keywords_from_url($url)
{
    $keywords = ['login', 'verify', 'secure', 'account', 'update', 'signin', 'wallet', 'bank', 'payment', 'password', 'otp'];
    $found = [];
    $lower = strtolower($url);
    foreach ($keywords as $keyword) {
        if (strpos($lower, $keyword) !== false) {
            $found[] = $keyword;
        }
    }
    return $found;
}

function domain_parts($url)
{
    $host = parse_url($url, PHP_URL_HOST);
    if (!$host) {
        $host = parse_url('http://' . $url, PHP_URL_HOST);
    }
    $host = strtolower($host ?: '');
    $parts = $host !== '' ? explode('.', $host) : [];
    $tld = count($parts) > 1 ? end($parts) : '';
    $subdomains = max(0, count($parts) - 2);
    return [$host, $tld, $subdomains];
}

function indicator_detected($value)
{
    $normalized = strtolower((string)$value);
    return in_array($normalized, ['detected', 'yes', 'true', '-1', '1'], true);
}

function pdf_escape_text($value)
{
    $text = preg_replace('/[^\x09\x0A\x0D\x20-\x7E]/', '', (string)$value);
    return str_replace(['\\', '(', ')'], ['\\\\', '\\(', '\\)'], $text);
}

function pdf_wrap_text($text, $maxChars = 88)
{
    $text = trim(preg_replace('/\s+/', ' ', (string)$text));
    if ($text === '') {
        return [''];
    }
    return explode("\n", wordwrap($text, $maxChars, "\n", true));
}

function pdf_build_document($title, $lines)
{
    $pages = [];
    $current = [];
    $y = 790;
    $lineHeight = 15;

    $addLine = function ($text, $size = 10, $bold = false) use (&$pages, &$current, &$y, $lineHeight) {
        if ($y < 55) {
            $pages[] = $current;
            $current = [];
            $y = 790;
        }
        $current[] = ['text' => $text, 'size' => $size, 'bold' => $bold, 'y' => $y];
        $y -= $lineHeight + ($size > 12 ? 5 : 0);
    };

    $addLine($title, 18, true);
    $addLine('Generated by ShieldURL Automated Response System', 10, false);
    $addLine('', 8, false);
    foreach ($lines as $line) {
        if (is_array($line)) {
            $text = $line['text'] ?? '';
            $size = $line['size'] ?? 10;
            $bold = !empty($line['bold']);
        } else {
            $text = (string)$line;
            $size = 10;
            $bold = false;
        }
        foreach (pdf_wrap_text($text, $size >= 13 ? 64 : 88) as $wrapped) {
            $addLine($wrapped, $size, $bold);
        }
    }
    if ($current) {
        $pages[] = $current;
    }

    $objects = [];
    $pagesObjectNumber = 2;
    $fontRegularObjectNumber = 3;
    $fontBoldObjectNumber = 4;
    $pageObjectNumbers = [];
    $contentObjectNumbers = [];
    $nextObject = 5;

    foreach ($pages as $_) {
        $pageObjectNumbers[] = $nextObject++;
        $contentObjectNumbers[] = $nextObject++;
    }

    $objects[1] = "<< /Type /Catalog /Pages {$pagesObjectNumber} 0 R >>";
    $objects[$pagesObjectNumber] = "<< /Type /Pages /Kids [" . implode(' ', array_map(fn($n) => "{$n} 0 R", $pageObjectNumbers)) . "] /Count " . count($pages) . " >>";
    $objects[$fontRegularObjectNumber] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";
    $objects[$fontBoldObjectNumber] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>";

    foreach ($pages as $index => $pageLines) {
        $stream = "BT\n";
        foreach ($pageLines as $line) {
            $font = $line['bold'] ? 'F2' : 'F1';
            $size = (int)$line['size'];
            $x = 48;
            $yPos = (int)$line['y'];
            $stream .= "/{$font} {$size} Tf\n";
            $stream .= "1 0 0 1 {$x} {$yPos} Tm\n";
            $stream .= "(" . pdf_escape_text($line['text']) . ") Tj\n";
        }
        $stream .= "ET\n";
        $contentObject = $contentObjectNumbers[$index];
        $pageObject = $pageObjectNumbers[$index];
        $objects[$contentObject] = "<< /Length " . strlen($stream) . " >>\nstream\n{$stream}endstream";
        $objects[$pageObject] = "<< /Type /Page /Parent {$pagesObjectNumber} 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 {$fontRegularObjectNumber} 0 R /F2 {$fontBoldObjectNumber} 0 R >> >> /Contents {$contentObject} 0 R >>";
    }

    ksort($objects);
    $pdf = "%PDF-1.4\n";
    $offsets = [0];
    foreach ($objects as $number => $body) {
        $offsets[$number] = strlen($pdf);
        $pdf .= "{$number} 0 obj\n{$body}\nendobj\n";
    }
    $xrefOffset = strlen($pdf);
    $pdf .= "xref\n0 " . (count($objects) + 1) . "\n";
    $pdf .= "0000000000 65535 f \n";
    for ($i = 1; $i <= count($objects); $i++) {
        $pdf .= sprintf("%010d 00000 n \n", $offsets[$i]);
    }
    $pdf .= "trailer\n<< /Size " . (count($objects) + 1) . " /Root 1 0 R >>\nstartxref\n{$xrefOffset}\n%%EOF";
    return $pdf;
}

function pdf_build_styled_report($data)
{
    $ops = [];
    $pageWidth = 595;
    $margin = 28;
    $contentWidth = $pageWidth - ($margin * 2);

    $rgb = function ($hex) {
        $hex = ltrim($hex, '#');
        return [
            hexdec(substr($hex, 0, 2)) / 255,
            hexdec(substr($hex, 2, 2)) / 255,
            hexdec(substr($hex, 4, 2)) / 255,
        ];
    };

    $setFill = function ($hex) use (&$ops, $rgb) {
        [$r, $g, $b] = $rgb($hex);
        $ops[] = sprintf('%.4F %.4F %.4F rg', $r, $g, $b);
    };
    $setStroke = function ($hex) use (&$ops, $rgb) {
        [$r, $g, $b] = $rgb($hex);
        $ops[] = sprintf('%.4F %.4F %.4F RG', $r, $g, $b);
    };
    $rect = function ($x, $y, $w, $h, $fill = '', $stroke = '') use (&$ops, $setFill, $setStroke) {
        if ($fill !== '') {
            $setFill($fill);
        }
        if ($stroke !== '') {
            $setStroke($stroke);
        }
        $mode = $fill !== '' && $stroke !== '' ? 'B' : ($fill !== '' ? 'f' : 'S');
        $ops[] = sprintf('%.2F %.2F %.2F %.2F re %s', $x, $y, $w, $h, $mode);
    };
    $text = function ($x, $y, $value, $size = 9, $bold = false, $color = '#0f172a') use (&$ops, $setFill) {
        $setFill($color);
        $font = $bold ? 'F2' : 'F1';
        $ops[] = "BT /{$font} {$size} Tf 1 0 0 1 " . sprintf('%.2F %.2F', $x, $y) . ' Tm (' . pdf_escape_text($value) . ') Tj ET';
    };
    $wrapText = function ($value, $chars) {
        return pdf_wrap_text((string)$value, $chars);
    };
    $sectionTitle = function ($title, $y) use (&$ops, $rect, $text, $margin, $contentWidth) {
        $rect($margin, $y - 22, $contentWidth, 22, '#f8fbff', '#dbe4ef');
        $text($margin + 8, $y - 14, strtoupper($title), 8, true, '#0b1f3a');
        return $y - 22;
    };

    $ops[] = 'q';
    $rect(0, 0, 595, 842, '#ffffff');

    $y = 806;
    $rect($margin, 744, $contentWidth, 68, '#0b1f3a');
    $text($margin + 16, 789, 'SHIELDURL SOC REPORT', 6.5, true, '#bfdbfe');
    $text($margin + 16, 768, $data['title'], 18, true, '#ffffff');
    $text(402, 792, 'Case ID', 6.5, false, '#bfdbfe');
    $text(500, 792, $data['case_id'], 7.5, true, '#ffffff');
    $text(402, 776, 'Generated', 6.5, false, '#bfdbfe');
    $text(500, 776, $data['generated'], 7.5, true, '#ffffff');
    $text(402, 760, 'Analyzed', 6.5, false, '#bfdbfe');
    $text(500, 760, $data['analyzed'], 7.5, true, '#ffffff');

    $y = 724;
    $statusColor = $data['category'] === 'safe' ? '#166534' : ($data['category'] === 'suspicious' ? '#b45309' : '#8f1418');
    $rect($margin, $y - 94, 190, 94, $statusColor);
    $text($margin + 14, $y - 28, 'THREAT STATUS', 7, true, '#ffffff');
    $text($margin + 14, $y - 55, strtoupper($data['display_status']), 20, true, '#ffffff');
    $text($margin + 14, $y - 79, 'SEVERITY: ' . strtoupper($data['severity']), 7, true, '#ffffff');

    $metrics = [
        ['Phishing Probability', $data['confidence']],
        ['Risk Level', $data['risk_level']],
        ['User Interaction Status', $data['interaction']],
        ['Risk Score', $data['risk_score']],
        ['Scan Duration', $data['scan_duration']],
        ['Detection Engine', $data['engine']],
    ];
    $mx = $margin + 198;
    $mw = ($contentWidth - 198 - 12) / 3;
    foreach ($metrics as $i => $metric) {
        $col = $i % 3;
        $row = intdiv($i, 3);
        $x = $mx + ($col * ($mw + 6));
        $cardY = $y - 43 - ($row * 48);
        $rect($x, $cardY, $mw, 40, '#ffffff', '#dbe4ef');
        $text($x + 6, $cardY + 26, strtoupper($metric[0]), 6.2, true, '#64748b');
        $text($x + 6, $cardY + 12, $metric[1], 8.8, true, '#0b1f3a');
    }

    $y = 610;
    $y = $sectionTitle('Scan Decision Explanation', $y);
    $decisionMetrics = [
        ['Phishing Probability', $data['confidence']],
        ['Detection Sensitivity', $data['threshold']],
        ['System Detection', $data['system_detection']],
        ['Safety Status', strtoupper($data['display_status'])],
    ];
    $boxW = ($contentWidth - 12) / 2;
    foreach ($decisionMetrics as $i => $metric) {
        $x = $margin + (($i % 2) * ($boxW + 12));
        $boxY = $y - 36 - (intdiv($i, 2) * 40);
        $rect($x, $boxY, $boxW, 32, '#ffffff', '#dbe4ef');
        $text($x + 8, $boxY + 19, strtoupper($metric[0]), 6.4, true, '#64748b');
        $text($x + 8, $boxY + 7, $metric[1], 8.8, true, '#0b1f3a');
    }
    $y -= 86;
    foreach ($wrapText($data['model_policy'], 116) as $line) {
        $text($margin + 8, $y, $line, 7.2, false, '#334155');
        $y -= 9;
    }
    $y -= 4;

    $y = $sectionTitle('URL Evidence', $y);
    $evidence = [
        ['Full URL', $data['url']],
        ['Domain', $data['domain']],
        ['Protocol', strtoupper($data['protocol'])],
        ['TLD', $data['tld'] ?: 'N/A'],
        ['HTTPS Status', $data['https_status']],
        ['Risk Indicators', $data['risk_indicators'] ?: 'No elevated URL indicators'],
    ];
    $y -= 12;
    foreach ($evidence as [$label, $value]) {
        $text($margin + 8, $y, strtoupper($label), 6.3, true, '#64748b');
        $first = true;
        foreach ($wrapText($value, $label === 'Full URL' ? 94 : 100) as $line) {
            $text($margin + 108, $y, $line, 7.2, $first, '#0f2747');
            $y -= 9;
            $first = false;
        }
        if ($first) $y -= 9;
        $setStroke('#e8eef6');
        $ops[] = sprintf('%.2F %.2F m %.2F %.2F l S', $margin + 8, $y + 4, $margin + $contentWidth - 8, $y + 4);
    }
    $y -= 4;

    $y = $sectionTitle('Incident Summary', $y);
    $y -= 12;
    foreach (array_slice($data['summary'], 0, 5) as $summary) {
        foreach ($wrapText('- ' . $summary, 112) as $line) {
            $text($margin + 8, $y, $line, 7.2, false, '#0f172a');
            $y -= 9;
        }
    }
    $y -= 4;

    $y = $sectionTitle('NIST Incident Response Timeline', $y);
    $actions = array_slice($data['actions'], 0, 12);
    $columns = [[$margin + 8, $y - 12], [$margin + ($contentWidth / 2) + 4, $y - 12]];
    foreach ($actions as $index => $action) {
        $col = $index >= 6 ? 1 : 0;
        [$x, $actionY] = $columns[$col];
        $text($x, $actionY, '- ' . $action, 6.9, false, '#0f172a');
        $columns[$col][1] -= 10;
    }
    $y = min($columns[0][1], $columns[1][1]) - 8;

    $y = max($y, 58);
    $rect($margin, $y - 24, $contentWidth, 24, '#fffbeb', '#f2bd35');
    $text($margin + 8, $y - 10, 'User Advisory', 7, true, '#92400e');
    foreach (array_slice($wrapText($data['advisory'], 112), 0, 2) as $i => $line) {
        $text($margin + 86, $y - 10 - ($i * 9), $line, 7, false, '#713f12');
    }

    $ops[] = 'Q';
    $stream = implode("\n", $ops) . "\n";

    $objects = [
        1 => '<< /Type /Catalog /Pages 2 0 R >>',
        2 => '<< /Type /Pages /Kids [5 0 R] /Count 1 >>',
        3 => '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
        4 => '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>',
        5 => '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents 6 0 R >>',
        6 => "<< /Length " . strlen($stream) . " >>\nstream\n{$stream}endstream",
    ];

    $pdf = "%PDF-1.4\n";
    $offsets = [0];
    foreach ($objects as $number => $body) {
        $offsets[$number] = strlen($pdf);
        $pdf .= "{$number} 0 obj\n{$body}\nendobj\n";
    }
    $xrefOffset = strlen($pdf);
    $pdf .= "xref\n0 7\n0000000000 65535 f \n";
    for ($i = 1; $i <= 6; $i++) {
        $pdf .= sprintf("%010d 00000 n \n", $offsets[$i]);
    }
    $pdf .= "trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n{$xrefOffset}\n%%EOF";
    return $pdf;
}

function browser_pdf_binary()
{
    $candidates = [
        getenv('LOCALAPPDATA') . '\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
        'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
        '/usr/bin/google-chrome',
        '/usr/bin/google-chrome-stable',
        '/usr/bin/chromium',
        '/usr/bin/chromium-browser',
        '/snap/bin/chromium',
    ];
    foreach ($candidates as $candidate) {
        if ($candidate && file_exists($candidate)) {
            return $candidate;
        }
    }
    return '';
}

function current_report_url($reportId)
{
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $script = $_SERVER['SCRIPT_NAME'] ?? '/ShieldURL/api/download_report.php';
    return $scheme . '://' . $host . $script . '?id=' . urlencode((string)$reportId) . '&pdf_source=1';
}

function render_html_pdf_with_browser($reportId, $filename)
{
    if (!function_exists('curl_init') || !function_exists('exec')) {
        return '';
    }

    $browser = browser_pdf_binary();
    if ($browser === '') {
        return '';
    }

    $sourceUrl = current_report_url($reportId);
    $ch = curl_init($sourceUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Cookie: ' . session_name() . '=' . session_id(),
    ]);
    $html = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if (!is_string($html) || trim($html) === '' || $httpCode < 200 || $httpCode >= 300) {
        return '';
    }

    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $base = rtrim(dirname(dirname($_SERVER['SCRIPT_NAME'] ?? '/ShieldURL/api/download_report.php')), '/\\');
    $appBase = $scheme . '://' . $host . ($base ? $base : '');
    $html = str_replace('src="../img/logo.png"', 'src="' . htmlspecialchars($appBase . '/img/logo.png', ENT_QUOTES, 'UTF-8') . '"', $html);

    $tmpBase = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'shieldurl_pdf_' . bin2hex(random_bytes(8));
    $htmlPath = $tmpBase . '.html';
    $pdfPath = $tmpBase . '.pdf';
    $profilePath = $tmpBase . '_profile';
    mkdir($profilePath, 0700, true);
    file_put_contents($htmlPath, $html);

    $fileUrl = 'file:///' . str_replace('\\', '/', realpath($htmlPath));
    $command = escapeshellarg($browser)
        . ' --headless --disable-gpu --no-first-run --disable-extensions'
        . ' --user-data-dir=' . escapeshellarg($profilePath)
        . ' --print-to-pdf=' . escapeshellarg($pdfPath)
        . ' --print-to-pdf-no-header '
        . escapeshellarg($fileUrl);
    exec($command, $output, $exitCode);

    $pdf = ($exitCode === 0 && file_exists($pdfPath)) ? file_get_contents($pdfPath) : '';
    @unlink($htmlPath);
    @unlink($pdfPath);
    if (is_dir($profilePath)) {
        $items = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($profilePath, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($items as $item) {
            $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        }
        @rmdir($profilePath);
    }

    return is_string($pdf) ? $pdf : '';
}

$db = new Database();
$conn = $db->getConnection();

$reportId = (int)$_GET['id'];
$isAdmin = ($_SESSION['role'] ?? '') === 'admin';
if ($isAdmin) {
    $stmt = $conn->prepare("SELECT * FROM url_logs WHERE id = ?");
    $stmt->execute([$reportId]);
} else {
    $stmt = $conn->prepare("SELECT * FROM url_logs WHERE id = ? AND user_id = ?");
    $stmt->execute([$reportId, $_SESSION['user_id']]);
}
$report = $stmt->fetch();

if (!$report) {
    audit_log($conn, 'report_download', 'Report download failed for report ID ' . $reportId, 'failed');
    http_response_code(404);
    exit('Report not found');
}

audit_log($conn, 'report_download', "Downloaded report #{$report['id']} for URL '{$report['url']}'", 'success');

$features = safe_decode($report['features'] ?? '', []);
$analysis = safe_decode($report['analysis_result'] ?? '', []);
$reportAudience = $isAdmin ? 'admin' : 'user';
$llmReport = shield_apply_verdict_report($analysis, $report, $analysis['llm_report'] ?? [], $reportAudience);
$mitre = $llmReport['mitre_attack_mapping'] ?? [];
$nistSteps = normalize_list($llmReport['containment_actions'] ?? []);
$irSteps = normalize_list($llmReport['eradication_recovery_actions'] ?? []);
$postIncidentSteps = normalize_list($llmReport['post_incident_recommendations'] ?? []);
$nistSteps = array_values(array_unique($nistSteps));
$irSteps = array_values(array_unique($irSteps));
$postIncidentSteps = array_values(array_unique($postIncidentSteps));
$url = $report['url'] ?? '';
[$domain, $tld, $subdomainCount] = domain_parts($url);

$status = strtolower((string)($analysis['status'] ?? ($report['status'] ?? 'safe')));
$confidenceRaw = shield_unit_probability($analysis['phishing_probability'] ?? ($analysis['confidence_score'] ?? ($report['confidence_score'] ?? 0)));
$confidence = $confidenceRaw * 100;
$confidenceNormalized = max(0, min(1, $confidence / 100));
$riskLevel = $analysis['risk_level'] ?? ($report['risk_level'] ?? 'low');
$selectedThresholdRaw = (float)($analysis['selected_threshold'] ?? ($analysis['ml']['selected_threshold'] ?? ($analysis['detection']['lexical_threshold'] ?? 0.5)));
$verdictCategory = shield_verdict_category($status, $analysis['display_status'] ?? ($analysis['overall']['display_verdict'] ?? ''), $riskLevel, $confidenceRaw, $selectedThresholdRaw);
$displayStatus = shield_display_status($verdictCategory, $analysis['display_status'] ?? ($analysis['overall']['display_verdict'] ?? $status));
$displayStatusNormalized = strtolower((string)$displayStatus);
$threatStatusClass = strpos($displayStatusNormalized, 'suspicious') !== false ? 'suspicious' : $verdictCategory;
$riskLevel = $verdictCategory === 'phishing' ? ($confidenceRaw < 0.70 ? 'medium' : 'high') : ($verdictCategory === 'suspicious' ? 'medium' : 'low');
$severity = severity_from($verdictCategory, $riskLevel, $confidenceNormalized);
$riskScore = number_format($confidenceNormalized * 10, 1);
$scanDuration = $analysis['debug']['php_total_seconds'] ?? $analysis['debug']['curl_total_seconds'] ?? 'N/A';
$engine = 'ShieldURL URL Detection + Incident Response';
$modelPolicy = $analysis['model_policy'] ?? shield_dynamic_policy_text(shield_verdict_category($status ?? '', $displayStatus ?? '', $riskLevel ?? ''));
if (preg_match('/lexical model|false negatives|threshold|recall|advanced URL detection/i', (string)$modelPolicy)) {
    $modelPolicy = shield_dynamic_policy_text(shield_verdict_category($status ?? '', $displayStatus ?? '', $riskLevel ?? ''));
}
$selectedThreshold = $selectedThresholdRaw <= 1 ? $selectedThresholdRaw * 100 : $selectedThresholdRaw;
$systemDetection = strtoupper($verdictCategory);
$protocol = parse_url($url, PHP_URL_SCHEME) ?: 'http';
$httpsStatus = $protocol === 'https' ? 'Valid HTTPS' : 'Non-HTTPS';
$keywords = suspicious_keywords_from_url($url);
$riskIndicators = shield_detection_evidence($url, $features);
$userAdvisory = $llmReport['user_advisory'] ?? '';
$executiveSummary = array_values(array_filter(array_merge(
    normalize_list($llmReport['incident_summary'] ?? ''),
    normalize_list($llmReport['detection_analysis'] ?? [])
)));
if (!in_array($modelPolicy, $executiveSummary, true)) {
    $executiveSummary[] = $modelPolicy;
}

if (strtolower((string)($_GET['format'] ?? '')) === 'pdf') {
    $reportTitle = $verdictCategory === 'safe' ? 'URL Safety Report' : ($verdictCategory === 'suspicious' ? 'URL Review Report' : 'Security Incident Report');
    $filename = 'ShieldURL_Report_' . str_pad((string)$report['id'], 6, '0', STR_PAD_LEFT) . '.pdf';
    $sessionName = session_name();
    $sessionId = session_id();
    session_write_close();
    if ($sessionName && $sessionId) {
        session_name($sessionName);
        session_id($sessionId);
    }
    $renderedPdf = render_html_pdf_with_browser($report['id'], $filename);
    if ($renderedPdf !== '') {
        header('Content-Type: application/pdf');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . strlen($renderedPdf));
        echo $renderedPdf;
        exit();
    }

    $allActions = array_values(array_filter(array_merge($nistSteps, $irSteps, $postIncidentSteps)));
    $riskIndicatorText = is_array($riskIndicators)
        ? implode(', ', array_map('strval', $riskIndicators))
        : (string)$riskIndicators;
    $pdf = pdf_build_styled_report([
        'title' => $reportTitle,
        'case_id' => '#' . str_pad((string)$report['id'], 6, '0', STR_PAD_LEFT),
        'generated' => date('Y-m-d H:i:s'),
        'analyzed' => (string)($report['analyzed_at'] ?? ''),
        'category' => $verdictCategory,
        'display_status' => (string)$displayStatus,
        'severity' => $severity,
        'confidence' => number_format($confidence, 2) . '%',
        'threshold' => number_format($selectedThreshold, 2) . '%',
        'system_detection' => $systemDetection,
        'risk_level' => ucfirst((string)$riskLevel),
        'interaction' => (string)($llmReport['user_interaction_status'] ?? 'Not collected'),
        'risk_score' => $riskScore . '/10',
        'scan_duration' => is_numeric($scanDuration) ? $scanDuration . 's' : (string)$scanDuration,
        'engine' => $engine,
        'model_policy' => (string)$modelPolicy,
        'url' => $url,
        'domain' => $domain,
        'protocol' => $protocol,
        'tld' => $tld,
        'https_status' => $httpsStatus,
        'risk_indicators' => $riskIndicatorText,
        'summary' => $executiveSummary,
        'actions' => $allActions,
        'advisory' => $userAdvisory ?: 'No advisory available.',
    ]);
    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . strlen($pdf));
    echo $pdf;
    exit();
}

$timeline = [];
if ($reportAudience === 'user') {
    $timeline = [
        ['Recommended Actions', 'Shield', $nistSteps],
        ['Follow-Up', 'Report', $irSteps],
        ['Additional Guidance', 'Shield', $postIncidentSteps],
    ];
} elseif ($verdictCategory === 'safe') {
    $timeline = [
        ['Review', 'Search', ['No major phishing indicators were detected.', 'NIST actions are not required.']],
        ['Admin Outcome', 'Shield', ['MITRE ATT&CK is not applicable.', 'No containment or recovery actions are required.']],
    ];
} elseif ($verdictCategory === 'suspicious') {
    $timeline = [
        ['Cautious Review', 'Search', array_merge(['Verify website legitimacy before allowing sensitive interaction.'], $nistSteps)],
        ['User Caution', 'Shield', $irSteps],
        ['Follow-Up', 'Report', $postIncidentSteps],
    ];
} else {
    $timeline = [
        ['Detection & Analysis', 'Search', array_merge(['Review the URL verdict, confidence, and technical indicators.'], array_slice($nistSteps, 0, 2))],
        ['Containment', 'Shield', $nistSteps],
        ['Eradication & Recovery', 'Clean', $irSteps],
        ['Post-Incident Actions', 'Report', $postIncidentSteps],
    ];
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Incident Report #<?php echo h($report['id']); ?> - ShieldURL</title>
    <style>
        * { box-sizing: border-box; }
        :root {
            --navy: #07182d;
            --blue: #123b6d;
            --accent: #2563eb;
            --gold: #d4a84a;
            --line: #dbe4ef;
            --muted: #64748b;
            --paper: #f6f9fc;
            --danger: #dc2626;
            --warn: #d97706;
            --safe: #15803d;
        }
        body {
            margin: 0;
            background: #e8eef6;
            color: #0f172a;
            font-family: "Segoe UI", Arial, sans-serif;
            line-height: 1.45;
            print-color-adjust: exact;
            -webkit-print-color-adjust: exact;
        }
        .report-page {
            width: min(1180px, calc(100% - 32px));
            margin: 24px auto;
            background: #ffffff;
            border: 1px solid var(--line);
            box-shadow: 0 18px 50px rgba(7, 24, 45, 0.18);
        }
        .report-header {
            display: grid;
            grid-template-columns: minmax(0, 1fr) auto;
            gap: 24px;
            padding: 28px 32px;
            background: linear-gradient(135deg, var(--navy) 0%, var(--blue) 72%, #1d4ed8 100%);
            color: #ffffff;
        }
        .brand-block {
            display: flex;
            gap: 18px;
            align-items: center;
            min-width: 0;
        }
        .brand-block img {
            width: 76px;
            height: 76px;
            object-fit: contain;
            filter: drop-shadow(0 8px 18px rgba(0,0,0,0.32));
        }
        .eyebrow {
            margin: 0 0 4px;
            color: #bfdbfe;
            text-transform: uppercase;
            font-size: 0.78rem;
            font-weight: 800;
            letter-spacing: 0.12em;
        }
        h1 {
            margin: 0;
            font-size: clamp(1.8rem, 4vw, 2.6rem);
            line-height: 1.1;
        }
        .header-meta {
            min-width: 280px;
            display: grid;
            gap: 8px;
            font-size: 0.92rem;
        }
        .meta-row {
            display: flex;
            justify-content: space-between;
            gap: 18px;
            border-bottom: 1px solid rgba(255,255,255,0.16);
            padding-bottom: 6px;
        }
        .meta-row span:first-child { color: #bfdbfe; }
        .report-actions {
            display: flex;
            gap: 8px;
            justify-content: flex-end;
            margin-top: 10px;
        }
        .report-btn {
            border: 1px solid rgba(255,255,255,0.32);
            background: rgba(255,255,255,0.12);
            color: #ffffff;
            border-radius: 8px;
            padding: 8px 12px;
            font: inherit;
            font-weight: 800;
            cursor: pointer;
            text-decoration: none;
        }
        .report-btn.primary {
            background: var(--gold);
            border-color: var(--gold);
            color: #08203c;
        }
        .report-body {
            padding: 26px 32px 34px;
            display: grid;
            gap: 20px;
        }
        .section-card {
            border: 1px solid var(--line);
            border-radius: 14px;
            background: #ffffff;
            overflow: hidden;
        }
        .section-title {
            margin: 0;
            padding: 16px 18px;
            background: #f8fbff;
            border-bottom: 1px solid var(--line);
            color: #0b1f3a;
            font-size: 1rem;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }
        .threat-card {
            display: grid;
            grid-template-columns: 1.2fr 2fr;
            gap: 0;
            border-radius: 16px;
            overflow: hidden;
            border: 1px solid var(--line);
            box-shadow: 0 12px 28px rgba(15, 23, 42, 0.08);
        }
        .threat-status {
            padding: 26px;
            background: #0b1f3a;
            color: #ffffff;
            display: grid;
            align-content: center;
            gap: 12px;
        }
        .threat-status.phishing { background: linear-gradient(145deg, #3b0d12, #991b1b); }
        .threat-status.suspicious { background: linear-gradient(145deg, #432006, #b45309); }
        .threat-status.safe { background: linear-gradient(145deg, #052e16, #166534); }
        .threat-icon {
            width: 54px;
            height: 54px;
            border-radius: 999px;
            display: grid;
            place-items: center;
            font-size: 1.8rem;
            font-weight: 900;
            background: rgba(255,255,255,0.16);
            border: 1px solid rgba(255,255,255,0.24);
        }
        .threat-status h2 {
            margin: 0;
            font-size: 2.25rem;
            letter-spacing: 0.04em;
            text-transform: uppercase;
        }
        .severity-badge {
            display: inline-flex;
            width: fit-content;
            padding: 6px 10px;
            border-radius: 999px;
            background: rgba(255,255,255,0.16);
            font-weight: 800;
            text-transform: uppercase;
            font-size: 0.78rem;
        }
        .metric-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 12px;
            padding: 20px;
            background: #f8fbff;
        }
        .metric {
            background: #ffffff;
            border: 1px solid var(--line);
            border-radius: 12px;
            padding: 14px;
        }
        .metric-label {
            color: var(--muted);
            font-size: 0.76rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            margin-bottom: 6px;
        }
        .metric-value {
            font-size: 1.24rem;
            font-weight: 850;
            color: #0b1f3a;
            word-break: break-word;
        }
        .evidence-panel {
            padding: 20px;
            display: grid;
            gap: 22px;
        }
        .evidence-block h3 {
            margin: 0 0 10px;
            font-size: 0.92rem;
            color: #0b1f3a;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .primary-evidence {
            width: 100%;
            border-collapse: collapse;
            background: #ffffff;
        }
        .primary-evidence th,
        .primary-evidence td {
            padding: 10px 0;
            border-bottom: 1px solid #e8eef6;
            text-align: left;
            vertical-align: top;
        }
        .primary-evidence th {
            width: 150px;
            color: var(--muted);
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }
        .primary-evidence td {
            color: #0f2747;
            font-weight: 750;
        }
        .url-truncate {
            display: block;
            max-width: 100%;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            cursor: help;
        }
        .indicator-strip {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }
        .risk-badge {
            display: inline-flex;
            align-items: center;
            border-radius: 999px;
            padding: 7px 11px;
            background: #eff6ff;
            color: #1e3a8a;
            border: 1px solid #bfdbfe;
            font-size: 0.84rem;
            font-weight: 800;
        }
        .risk-badge.warn {
            background: #fff7ed;
            color: #9a3412;
            border-color: #fed7aa;
        }
        .evidence-value {
            font-weight: 800;
            color: #0f2747;
            word-break: break-word;
        }
        .summary-list,
        .timeline-list {
            margin: 0;
            padding-left: 18px;
        }
        .summary-list li,
        .timeline-list li {
            margin: 6px 0;
        }
        .summary-content {
            padding: 18px;
        }
        .timeline {
            display: grid;
            gap: 12px;
            padding: 18px;
        }
        .timeline-card {
            display: grid;
            grid-template-columns: 52px minmax(0, 1fr);
            gap: 14px;
            padding: 14px;
            border: 1px solid var(--line);
            border-radius: 12px;
            background: #fbfdff;
        }
        .timeline-num {
            width: 42px;
            height: 42px;
            border-radius: 12px;
            display: grid;
            place-items: center;
            background: #dbeafe;
            color: #1e3a8a;
            font-weight: 900;
        }
        .timeline-card h3 {
            margin: 0 0 6px;
            color: #0b1f3a;
            font-size: 1rem;
        }
        .tag-wrap {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            padding: 18px;
        }
        .mitre-tag {
            border: 1px solid #bfdbfe;
            background: #eff6ff;
            color: #1e3a8a;
            border-radius: 999px;
            padding: 8px 12px;
            font-weight: 800;
        }
        .warning-card {
            display: grid;
            grid-template-columns: 46px minmax(0, 1fr);
            gap: 14px;
            padding: 18px;
            border: 1px solid #fbbf24;
            background: #fffbeb;
            color: #78350f;
            border-radius: 14px;
        }
        .warning-icon {
            width: 42px;
            height: 42px;
            border-radius: 12px;
            display: grid;
            place-items: center;
            background: #f59e0b;
            color: #ffffff;
            font-weight: 900;
            font-size: 1.2rem;
        }
        .tech-details {
            border: 1px solid var(--line);
            border-radius: 14px;
            overflow: hidden;
        }
        .tech-details summary {
            cursor: pointer;
            padding: 16px 18px;
            background: #0b1f3a;
            color: #ffffff;
            font-weight: 850;
        }
        .tech-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 10px;
            padding: 18px;
            background: #f8fbff;
        }
        .tech-item {
            border: 1px solid var(--line);
            border-radius: 10px;
            padding: 10px;
            background: #ffffff;
        }
        .footer {
            border-top: 1px solid var(--line);
            padding: 16px 32px 26px;
            color: var(--muted);
            font-size: 0.86rem;
            text-align: center;
        }
        @media (max-width: 900px) {
            .report-header,
            .threat-card {
                grid-template-columns: 1fr;
            }
            .header-meta {
                min-width: 0;
            }
            .metric-grid,
            .tech-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        @media (max-width: 620px) {
            .report-page {
                width: 100%;
                margin: 0;
            }
            .report-header,
            .report-body,
            .footer {
                padding-left: 18px;
                padding-right: 18px;
            }
            .metric-grid,
            .tech-grid {
                grid-template-columns: 1fr;
            }
            .primary-evidence th,
            .primary-evidence td {
                display: block;
                width: 100%;
                padding: 6px 0;
            }
            .primary-evidence tr {
                display: block;
                padding: 8px 0;
                border-bottom: 1px solid #e8eef6;
            }
            .primary-evidence th,
            .primary-evidence td {
                border-bottom: none;
            }
            .report-actions {
                justify-content: flex-start;
                flex-wrap: wrap;
            }
        }
        @media print {
            @page {
                size: A4 portrait;
                margin: 5mm;
            }
            * {
                box-shadow: none !important;
                text-shadow: none !important;
            }
            body {
                background: #ffffff;
                color: #0f172a;
                font-size: 9px;
                line-height: 1.18;
                print-color-adjust: exact;
                -webkit-print-color-adjust: exact;
            }
            .report-page {
                width: 100%;
                min-height: calc(297mm - 10mm);
                margin: 0;
                border: none;
                box-shadow: none;
            }
            .report-actions,
            .no-print,
            .tech-details,
            .footer,
            .threat-icon {
                display: none !important;
            }
            .report-header {
                display: grid;
                grid-template-columns: 1fr 1.05fr;
                gap: 7px;
                padding: 9px 10px;
                background: #0b1f3a !important;
            }
            .brand-block {
                gap: 8px;
            }
            .brand-block img {
                width: 36px;
                height: 36px;
            }
            .eyebrow {
                font-size: 6.6px;
                margin-bottom: 1px;
                letter-spacing: 0.08em;
            }
            h1 {
                font-size: 15.5px;
                line-height: 1.05;
            }
            .header-meta {
                min-width: 0;
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 2px 8px;
                font-size: 7.4px;
                align-content: center;
            }
            .meta-row {
                border-bottom: none;
                padding-bottom: 0;
                gap: 5px;
            }
            .report-body {
                padding: 8px 0 0;
                gap: 6px;
            }
            .threat-card {
                grid-template-columns: 0.72fr 2fr;
                border-radius: 6px;
                break-inside: avoid;
            }
            .threat-status {
                padding: 9px 10px;
                gap: 4px;
            }
            .threat-status h2 {
                font-size: 16px;
                line-height: 1.05;
            }
            .severity-badge {
                padding: 3px 6px;
                font-size: 7px;
            }
            .metric-grid {
                grid-template-columns: repeat(3, minmax(0, 1fr));
                gap: 5px;
                padding: 6px;
            }
            .metric {
                border-radius: 5px;
                padding: 5px 6px;
            }
            .metric-label {
                font-size: 6.5px;
                margin-bottom: 2px;
                letter-spacing: 0.04em;
            }
            .metric-value {
                font-size: 9.8px;
                line-height: 1.08;
            }
            .section-card {
                border-radius: 6px;
                break-inside: avoid;
            }
            .section-title {
                padding: 5px 7px;
                font-size: 8.4px;
                letter-spacing: 0.035em;
            }
            .evidence-panel {
                padding: 5px 7px;
                gap: 5px;
            }
            .evidence-block h3 {
                font-size: 8px;
                margin-bottom: 2px;
            }
            .primary-evidence th,
            .primary-evidence td {
                padding: 1.5px 0;
            }
            .primary-evidence th {
                width: 82px;
                font-size: 6.6px;
            }
            .primary-evidence td {
                font-size: 8px;
            }
            .indicator-strip {
                gap: 4px;
            }
            .risk-badge {
                padding: 3px 6px;
                font-size: 7.5px;
            }
            .summary-content {
                padding: 5px 7px;
            }
            .summary-list,
            .timeline-list {
                padding-left: 10px;
            }
            .summary-list li,
            .timeline-list li {
                margin: 1px 0;
            }
            .timeline {
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 5px;
                padding: 5px 7px;
            }
            .timeline-card {
                grid-template-columns: 22px minmax(0, 1fr);
                gap: 6px;
                padding: 5px 6px;
                border-radius: 5px;
            }
            .timeline-num {
                width: 18px;
                height: 18px;
                border-radius: 4px;
                font-size: 8px;
            }
            .timeline-card h3 {
                font-size: 8px;
                margin: 0 0 2px;
            }
            .tag-wrap {
                gap: 3px;
                padding: 4px 6px;
            }
            .mitre-tag {
                padding: 3px 6px;
                font-size: 7.5px;
            }
            .warning-card {
                grid-template-columns: minmax(0, 1fr);
                gap: 0;
                padding: 5px 7px;
                border-radius: 6px;
                break-inside: avoid;
            }
            .warning-icon {
                display: none;
            }
            .warning-card h2 {
                font-size: 8.5px !important;
                margin-bottom: 1px !important;
            }
            .warning-card p {
                font-size: 7.6px;
            }
            .url-truncate {
                max-width: 115mm;
            }
            .section-card,
            .threat-card,
            .warning-card,
            .timeline-card {
                break-inside: avoid;
                page-break-inside: avoid;
            }
            p,
            ul {
                margin-top: 0;
                margin-bottom: 0;
            }
        }
    </style>
</head>

<body>
    <main class="report-page">
        <header class="report-header">
            <div class="brand-block">
                <img src="../img/logo.png" alt="ShieldURL logo">
                <div>
                    <p class="eyebrow">ShieldURL SOC Report</p>
                    <h1><?php echo h($verdictCategory === 'safe' ? 'URL Safety Report' : ($verdictCategory === 'suspicious' ? 'URL Review Report' : 'Security Incident Report')); ?></h1>
                </div>
            </div>
            <div class="header-meta">
                <div class="meta-row"><span>Case ID</span><strong>#<?php echo h(str_pad((string)$report['id'], 6, '0', STR_PAD_LEFT)); ?></strong></div>
                <div class="meta-row"><span>Generated</span><strong><?php echo h(date('Y-m-d H:i:s')); ?></strong></div>
                <div class="meta-row"><span>Analyzed</span><strong><?php echo h($report['analyzed_at']); ?></strong></div>
                <div class="meta-row"><span>Analyst</span><strong>ShieldURL AI Assistant</strong></div>
                <div class="report-actions">
                    <button class="report-btn" type="button" onclick="window.print()">Print PDF</button>
                    <a class="report-btn primary" href="?id=<?php echo h($report['id']); ?>&format=pdf">Download PDF</a>
                </div>
            </div>
        </header>

        <section class="report-body">
            <div class="threat-card">
                <div class="threat-status <?php echo h($threatStatusClass); ?>">
                    <div class="threat-icon"><?php echo h(status_icon($threatStatusClass)); ?></div>
                    <div>
                        <p class="eyebrow">Threat Status</p>
                        <h2><?php echo h(strtoupper($displayStatus)); ?></h2>
                    </div>
                    <span class="severity-badge">Severity: <?php echo h($severity); ?></span>
                </div>
                <div class="metric-grid">
                    <div class="metric"><div class="metric-label">Phishing Probability</div><div class="metric-value"><?php echo h(number_format($confidence, 2)); ?>%</div></div>
                    <div class="metric"><div class="metric-label">Risk Level</div><div class="metric-value"><?php echo h(ucfirst((string)$riskLevel)); ?></div></div>
                    <div class="metric"><div class="metric-label">User Interaction Status</div><div class="metric-value"><?php echo h($llmReport['user_interaction_status'] ?? 'Not collected'); ?></div></div>
                    <div class="metric"><div class="metric-label">Risk Score</div><div class="metric-value"><?php echo h($riskScore); ?>/10</div></div>
                    <div class="metric"><div class="metric-label">Scan Duration</div><div class="metric-value"><?php echo h(is_numeric($scanDuration) ? $scanDuration . 's' : $scanDuration); ?></div></div>
                    <div class="metric"><div class="metric-label">Detection Engine</div><div class="metric-value"><?php echo h($engine); ?></div></div>
                </div>
            </div>

            <section class="section-card">
                <h2 class="section-title">Scan Decision Explanation</h2>
                <div class="metric-grid">
                    <div class="metric"><div class="metric-label">Phishing Probability</div><div class="metric-value"><?php echo h(number_format($confidence, 2)); ?>%</div></div>
                    <div class="metric"><div class="metric-label">Detection Sensitivity</div><div class="metric-value"><?php echo h(number_format($selectedThreshold, 2)); ?>%</div></div>
                    <div class="metric"><div class="metric-label">System Detection</div><div class="metric-value"><?php echo h($systemDetection); ?></div></div>
                    <div class="metric"><div class="metric-label">Safety Status</div><div class="metric-value"><?php echo h(strtoupper($displayStatus)); ?></div></div>
                </div>
                <p style="margin: 0.85rem 0 0; color: #475569;">
                    <?php if ($verdictCategory === 'safe'): ?>
                        <?php echo h($modelPolicy); ?> No major phishing indicators were detected in the current scan. No immediate action is required.
                    <?php elseif ($verdictCategory === 'suspicious'): ?>
                        <?php echo h($modelPolicy); ?> Potentially suspicious results show suspicious characteristics, but are not confirmed phishing based on the current evidence. Review the URL carefully before interacting with it.
                    <?php else: ?>
                        <?php echo h($modelPolicy); ?> The phishing verdict requires incident response review and user protection actions.
                    <?php endif; ?>
                </p>
            </section>

            <section class="section-card">
                <h2 class="section-title">URL Evidence</h2>
                <div class="evidence-panel">
                    <div class="evidence-block">
                        <h3>Primary Evidence</h3>
                        <table class="primary-evidence">
                            <tr>
                                <th>Full URL</th>
                                <td><span class="url-truncate" title="<?php echo h($url); ?>"><?php echo h($url); ?></span></td>
                            </tr>
                            <?php if ($domain !== ''): ?>
                                <tr><th>Domain</th><td><?php echo h($domain); ?></td></tr>
                            <?php endif; ?>
                            <tr><th>Protocol</th><td><?php echo h(strtoupper($protocol)); ?></td></tr>
                            <?php if ($tld !== ''): ?>
                                <tr><th>TLD</th><td>.<?php echo h($tld); ?></td></tr>
                            <?php endif; ?>
                            <tr><th>HTTPS Status</th><td><?php echo h($httpsStatus); ?></td></tr>
                        </table>
                    </div>
                    <div class="evidence-block">
                        <h3>Risk Indicators</h3>
                        <div class="indicator-strip">
                            <?php if (!empty($riskIndicators)): ?>
                                <?php foreach ($riskIndicators as $indicator): ?>
                                    <span class="risk-badge warn"><?php echo h($indicator); ?></span>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <span class="risk-badge">No elevated URL indicators</span>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </section>

            <section class="section-card">
                <h2 class="section-title">Incident Summary</h2>
                <div class="summary-content">
                    <p class="metric-label">Executive Summary</p>
                    <ul class="summary-list">
                        <?php foreach (array_slice($executiveSummary, 0, 5) as $summary): ?>
                            <li><?php echo h($summary); ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            </section>

            <section class="section-card">
                <h2 class="section-title"><?php echo h($reportAudience === 'admin' && $verdictCategory === 'phishing' ? 'NIST Incident Response Timeline' : 'Recommended Guidance'); ?></h2>
                <div class="timeline">
                    <?php foreach ($timeline as $index => $phase): ?>
                        <div class="timeline-card">
                            <div class="timeline-num"><?php echo h($index + 1); ?></div>
                            <div>
                                <h3><?php echo h($phase[0]); ?></h3>
                                <ul class="timeline-list">
                                    <?php foreach (array_slice(normalize_list($phase[2]), 0, 4) as $step): ?>
                                        <li><?php echo h($step); ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </section>

            <?php if ($verdictCategory !== 'safe'): ?>
            <section class="section-card">
                <h2 class="section-title"><?php echo h($verdictCategory === 'suspicious' ? 'Potentially Related MITRE ATT&CK Mapping' : 'MITRE ATT&CK Mapping'); ?></h2>
                <div class="tag-wrap">
                    <?php if (!empty($mitre)): ?>
                        <?php foreach ($mitre as $item): ?>
                            <?php
                            $techId = is_array($item) ? ($item['id'] ?? $item['technique_id'] ?? '') : '';
                            $techName = is_array($item) ? ($item['name'] ?? $item['technique'] ?? $item['description'] ?? '') : (string)$item;
                            ?>
                            <span class="mitre-tag"><?php echo h(trim($techId . ($techId && $techName ? ' - ' : '') . $techName)); ?></span>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <span class="mitre-tag">No ATT&CK technique mapped</span>
                    <?php endif; ?>
                </div>
            </section>
            <?php endif; ?>

            <section class="warning-card">
                <div class="warning-icon">!</div>
                <div>
                    <h2 style="margin: 0 0 6px; font-size: 1.08rem;">User Advisory</h2>
                    <p style="margin: 0;"><?php echo h($userAdvisory); ?></p>
                </div>
            </section>

            <details class="tech-details">
                <summary>View Technical Analysis</summary>
                <div class="tech-grid">
                    <?php if (!empty($features)): ?>
                        <?php foreach ($features as $key => $value): ?>
                            <div class="tech-item">
                                <div class="metric-label"><?php echo h(feature_label($key)); ?></div>
                                <div class="evidence-value"><?php echo h(display_feature_value($value)); ?></div>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div class="tech-item">
                            <div class="metric-label">Technical Features</div>
                            <div class="evidence-value">No feature extraction data available.</div>
                        </div>
                    <?php endif; ?>
                </div>
            </details>
        </section>

        <footer class="footer">
            Generated by ShieldURL Automated Response System. Debug output, stack traces, and runtime warnings are suppressed from this report.
        </footer>
    </main>
    <script>
        window.addEventListener('beforeprint', () => {
            document.querySelectorAll('details.tech-details').forEach(details => details.open = true);
        });
    </script>
</body>

</html>
