<?php
// Ensure we always return JSON and avoid HTML error output
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);
ini_set('max_execution_time', '240');
set_time_limit(240);

require_once '../config/db.php';
require_once '../shared/audit.php';

header('Content-Type: application/json');

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// For CLI testing, assign a default user id so we can exercise the endpoint from CLI
if (php_sapi_name() === 'cli') {
    if (!isset($_SESSION['user_id'])) {
        $_SESSION['user_id'] = 1;
    }
}

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'message' => 'Not authenticated']);
    exit();
}

$raw_input = null;
if (php_sapi_name() === 'cli') {
    global $argv;
    $raw_input = isset($argv[1]) ? $argv[1] : null;
} else {
    $raw_input = file_get_contents('php://input');
}

$data = json_decode($raw_input, true);
if (!$data || empty($data['url'])) {
    echo json_encode(['success' => false, 'message' => 'Missing url']);
    exit();
}

$url = trim($data['url']);
$apiStart = microtime(true);

// ----------------------------
// Call FastAPI /scan
// ----------------------------
$apiUrl = "http://127.0.0.1:8000/scan";
$payload = json_encode([
    "url" => $url,
    "clicked" => $data["clicked"] ?? null
]);
$curlDebugPath = __DIR__ . '/../tmp/analyze_curl_debug.log';
$curlVerboseHandle = fopen($curlDebugPath, 'ab');

// Ensure cURL exists
if (!function_exists('curl_init')) {
    echo json_encode([
        "success" => false,
        "message" => "PHP cURL extension is not enabled. Enable php_curl in php.ini and restart Apache."
    ]);
    exit();
}

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $apiUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, ["Content-Type: application/json", "Accept: application/json"]);
curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
curl_setopt($ch, CURLOPT_TIMEOUT, 180);
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
curl_setopt($ch, CURLOPT_VERBOSE, true);
if ($curlVerboseHandle) {
    fwrite($curlVerboseHandle, "\n[" . date('c') . "] POST {$apiUrl} payload=" . $payload . "\n");
    curl_setopt($ch, CURLOPT_STDERR, $curlVerboseHandle);
}

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curlErr = curl_error($ch);
$curlErrNo = curl_errno($ch);
$curlTotalTime = curl_getinfo($ch, CURLINFO_TOTAL_TIME);
curl_close($ch);
if ($curlVerboseHandle) {
    fwrite($curlVerboseHandle, "curl_errno={$curlErrNo} curl_error={$curlErr} http_code={$httpCode} total={$curlTotalTime}\n");
    fclose($curlVerboseHandle);
}

$api = null;
if (is_string($response) && trim($response) !== '') {
    $decoded = json_decode($response, true);
    if (is_array($decoded)) {
        $api = $decoded;
    }
}

if ($response === false) {
    $timedOut = in_array($curlErrNo, [CURLE_OPERATION_TIMEDOUT], true)
        || stripos((string)$curlErr, 'timed out') !== false;

    if ($timedOut) {
        echo json_encode([
            "success" => false,
            "url" => $url,
            "status" => "unknown",
            "risk_level" => "unknown",
            "confidence_score" => 0,
            "features" => [],
            "clicked" => $data["clicked"] ?? null,
            "llm_summary" => "",
            "llm_report" => [],
            "llm" => [],
            "mitre_techniques" => [],
            "nist_response" => [],
            "incident_response" => [],
            "user_advisory" => "",
            "message" => "FastAPI request timed out before a response was received.",
            "debug" => [
                "api_url" => $apiUrl,
                "curl_errno" => $curlErrNo,
                "curl_error" => $curlErr,
                "curl_total_seconds" => $curlTotalTime,
                "php_total_seconds" => round(microtime(true) - $apiStart, 3),
                "curl_debug_log" => $curlDebugPath,
            ],
        ]);
        exit();
    }

    echo json_encode([
        "success" => false,
        "message" => "FastAPI scan failed",
        "http_code" => $httpCode,
        "curl_errno" => $curlErrNo,
        "curl_error" => $curlErr,
        "raw_response" => $response,
        "debug" => [
            "api_url" => $apiUrl,
            "curl_total_seconds" => $curlTotalTime,
            "php_total_seconds" => round(microtime(true) - $apiStart, 3),
            "curl_debug_log" => $curlDebugPath,
        ],
    ]);
    exit();
}

if ($httpCode !== 200 && !$api) {
    echo json_encode([
        "success" => false,
        "message" => "FastAPI scan failed",
        "http_code" => $httpCode,
        "curl_errno" => $curlErrNo,
        "curl_error" => $curlErr,
        "raw_response" => $response,
        "debug" => [
            "api_url" => $apiUrl,
            "curl_total_seconds" => $curlTotalTime,
            "php_total_seconds" => round(microtime(true) - $apiStart, 3),
            "curl_debug_log" => $curlDebugPath,
        ],
    ]);
    exit();
}

if (!$api) {
    echo json_encode([
        "success" => false,
        "message" => "Invalid JSON from FastAPI",
        "raw_response" => $response,
        "debug" => [
            "api_url" => $apiUrl,
            "curl_total_seconds" => $curlTotalTime,
            "php_total_seconds" => round(microtime(true) - $apiStart, 3),
            "curl_debug_log" => $curlDebugPath,
        ],
    ]);
    exit();
}

// ----------------------------
// Normalize FastAPI response to your UI/DB format
// ----------------------------
$detection = is_array($api["detection"] ?? null) ? $api["detection"] : [];
$overallVerdict = strtoupper($api["overall"]["verdict"] ?? ($detection["final_verdict"] ?? "UNKNOWN"));
$overallStatus = strtoupper($api["overall"]["status"] ?? ($detection["final_verdict"] ?? "UNKNOWN"));
$mlStatus = strtoupper($api["ml"]["status"] ?? "UNKNOWN");
$hasDetection = !empty($detection) || !empty($api["overall"] ?? []) || !empty($api["ml"] ?? []);

// If overall verdict says phishing, trust it.
// Otherwise fall back to ML status.
$isPhishing =
    in_array($overallVerdict, ["PHISHING", "LIKELY_PHISHING", "CONFIRMED_PHISHING"], true) ||
    ($overallStatus === "PHISHING") ||
    ($mlStatus === "PHISHING");

$result = [
    "success" => (bool)($api["success"] ?? true) || $hasDetection,
    "url" => $api["url"] ?? $url,
    "clicked" => $api["clicked"] ?? ($data["clicked"] ?? null),
    "status" => $isPhishing ? "phishing" : "safe",
    "risk_level" => strtolower($api["overall"]["risk_level"] ?? ($detection["risk_level"] ?? ($api["ml"]["risk_level"] ?? "low"))),
    "confidence_score" => floatval($api["ml"]["confidence_score"] ?? ($detection["confidence_score"] ?? 0)),
    "features" => $api["ml"]["features"] ?? ($detection["features"] ?? []),
    "llm_summary" => $api["llm"]["incident_summary"] ?? ($api["llm_report"]["incident_summary"] ?? ""),
    "llm_report" => $api["llm_report"] ?? ($api["llm"] ?? []),
    "mitre_techniques" => $api["llm"]["mitre_attack_mapping"] ?? ($api["llm_report"]["mitre_attack_mapping"] ?? ($api["llm"]["mitre_techniques"] ?? [])),
    "nist_response" => $api["llm"]["containment_actions"] ?? ($api["llm_report"]["containment_actions"] ?? ($api["llm"]["nist_response"] ?? [])),
    "incident_response" => $api["llm"]["eradication_recovery_actions"] ?? ($api["llm_report"]["eradication_recovery_actions"] ?? ($api["llm"]["incident_response"] ?? [])),
    "user_advisory" => $api["llm"]["user_advisory"] ?? ($api["llm_report"]["user_advisory"] ?? ""),

    // Keep these extra fields for debugging / reports
    "detection" => $detection,
    "ml" => $api["ml"] ?? [],
    "heuristics" => $api["heuristics"] ?? [],
    "overall" => $api["overall"] ?? [],
    "llm" => $api["llm"] ?? ($api["llm_report"] ?? []),
    "timing" => $api["timing"] ?? [],
    "debug" => [
        "fastapi_http_code" => $httpCode,
        "curl_total_seconds" => $curlTotalTime,
        "php_total_seconds" => round(microtime(true) - $apiStart, 3),
        "curl_debug_log" => $curlDebugPath,
        "curl_errno" => $curlErrNo,
        "curl_error" => $curlErr,
    ],
];

if (!$result["success"]) {
    $result["message"] = $api["message"] ?? "Scan failed";
}

// ----------------------------
// Log to DB (best effort)
// ----------------------------
$auditLogged = false;
try {
    $db = new Database();
    $conn = $db->getConnection();

    $stmt = $conn->prepare("
        INSERT INTO url_logs
            (user_id, url, status, risk_level, confidence_score, features, llm_summary, mitre_attack_json, nist_response_json, incident_response_text, user_advisory_text, analysis_result)
        VALUES
            (:user_id, :url, :status, :risk_level, :confidence, :features, :llm_summary, :mitre, :nist, :ir, :advisory, :result)
    ");

    if ($result["success"]) {
        $stmt->execute([
        ':user_id' => $_SESSION['user_id'],
        ':url' => $url,
        ':status' => $result['status'], // 'safe' or 'phishing'
        ':risk_level' => $result['risk_level'] ?? 'low',
        ':confidence' => $result['confidence_score'],
        ':features' => json_encode($result['features'] ?? []),

        // These fields are optional in your current setup
        ':llm_summary' => $result['llm_summary'] ?? '',
        ':mitre' => json_encode($result['mitre_techniques'] ?? []),
        ':nist' => json_encode($result['nist_response'] ?? []),
        ':ir' => json_encode($result['incident_response'] ?? []),
        ':advisory' => $result['user_advisory'] ?? '',

        ':result' => json_encode($result)
    ]);

        $result['report_id'] = $conn->lastInsertId();
        audit_log($conn, 'url_scan', "Scanned URL '{$url}' with status '{$result['status']}'", 'success');
        $auditLogged = true;
    }

} catch (Exception $e) {
    $result['debug']['db_error'] = $e->getMessage();
    if (isset($conn)) {
        audit_log($conn, 'url_scan', "URL scan failed for '{$url}': " . $e->getMessage(), 'failed');
        $auditLogged = true;
    }
}

if (!$auditLogged && isset($conn)) {
    audit_log($conn, 'url_scan', "URL scan failed for '{$url}': " . ($result['message'] ?? 'Unknown error'), 'failed');
}

// Return JSON
echo json_encode($result);
