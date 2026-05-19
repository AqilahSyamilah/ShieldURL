<?php
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);
ini_set('max_execution_time', '90');
set_time_limit(90);

require_once '../config/db.php';

header('Content-Type: application/json');

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'message' => 'Not authenticated']);
    exit();
}

function chat_json($payload, $statusCode = 200)
{
    http_response_code($statusCode);
    echo json_encode($payload);
    exit();
}

function chat_decode_json($value, $fallback = [])
{
    if (is_array($value)) {
        return $value;
    }
    if (!is_string($value) || trim($value) === '') {
        return $fallback;
    }
    $decoded = json_decode($value, true);
    return is_array($decoded) ? $decoded : $fallback;
}

function chat_safe_list($value)
{
    if (is_array($value)) {
        return array_values(array_filter($value, function ($item) {
            return $item !== null && $item !== '';
        }));
    }
    if (is_string($value) && trim($value) !== '') {
        $decoded = json_decode($value, true);
        if (is_array($decoded)) {
            return chat_safe_list($decoded);
        }
        return [trim($value)];
    }
    return [];
}

function chat_redact_question($question)
{
    $redacted = preg_replace('/\b(password|passcode|otp|one[-\s]?time code|pin|card number|cvv|token|secret)\b\s*(?:is|=|:)?\s*[\w\-@.]{2,}/i', '[REDACTED]', $question);
    $redacted = preg_replace('/\b(?:\d[ -]?){12,19}\b/', '[REDACTED]', $redacted);
    $redacted = preg_replace('/\b(password|passcode|otp|one[-\s]?time code|pin|bank(?:ing)?|card number|cvv|token|secret)\b/i', '[REDACTED]', $redacted);
    return substr($redacted, 0, 500);
}

function chat_rate_limited()
{
    $now = time();
    if (!isset($_SESSION['chat_request_times']) || !is_array($_SESSION['chat_request_times'])) {
        $_SESSION['chat_request_times'] = [];
    }

    $_SESSION['chat_request_times'] = array_values(array_filter($_SESSION['chat_request_times'], function ($timestamp) use ($now) {
        return ($now - intval($timestamp)) <= 60;
    }));

    if (count($_SESSION['chat_request_times']) >= 12) {
        return true;
    }

    $_SESSION['chat_request_times'][] = $now;
    return false;
}

$rawInput = file_get_contents('php://input');
$data = json_decode($rawInput, true);
if (!is_array($data)) {
    chat_json(['success' => false, 'message' => 'Invalid JSON request'], 400);
}

$rawQuestion = $data['user_question'] ?? ($data['message'] ?? ($data['prompt'] ?? ($data['question'] ?? '')));
$question = is_string($rawQuestion) ? trim($rawQuestion) : '';
if ($question === '') {
    chat_json(['success' => false, 'message' => 'message is required'], 400);
}
if (strlen($question) > 500) {
    chat_json(['success' => false, 'message' => 'user_question must be 500 characters or fewer'], 400);
}

$scanId = isset($data['scan_id']) ? intval($data['scan_id']) : 0;
$clientScanContext = isset($data['scan_context']) && is_array($data['scan_context']) ? $data['scan_context'] : [];
$assistantStyle = isset($data['assistant_response_style']) ? strtolower(trim(strval($data['assistant_response_style']))) : 'simple';
if (!in_array($assistantStyle, ['simple', 'technical', 'executive'], true)) {
    $assistantStyle = 'simple';
}

if (chat_rate_limited()) {
    chat_json([
        'success' => false,
        'answer' => 'Too many assistant requests. Please wait a moment and try again.',
        'used_scan_context' => true,
        'safety_notice' => 'Detection result was not modified by the LLM.'
    ], 429);
}

$db = null;
$conn = null;
$scanContext = $clientScanContext;

if ($scanId > 0) {
    $db = new Database();
    $conn = $db->getConnection();

    $stmt = $conn->prepare('SELECT * FROM url_logs WHERE id = ? AND user_id = ? LIMIT 1');
    $stmt->execute([$scanId, $_SESSION['user_id']]);
    $scan = $stmt->fetch();
    if (!$scan && empty($clientScanContext)) {
        chat_json(['success' => false, 'message' => 'Scan result not found for this session.'], 404);
    }

    if ($scan) {
        $analysis = chat_decode_json($scan['analysis_result'] ?? '', []);
        $llm = chat_decode_json($analysis['llm_report'] ?? ($analysis['llm'] ?? []), []);
        $features = chat_decode_json($scan['features'] ?? ($analysis['features'] ?? []), []);
        $mitre = chat_safe_list($scan['mitre_attack_json'] ?? ($analysis['mitre_techniques'] ?? ($llm['mitre_attack_mapping'] ?? [])));
        $nistContainment = chat_safe_list($llm['containment_actions'] ?? ($analysis['nist_response'] ?? []));
        $nistRecovery = chat_safe_list($llm['eradication_recovery_actions'] ?? ($analysis['incident_response'] ?? []));
        $nistPostIncident = chat_safe_list($llm['post_incident_recommendations'] ?? []);
        $heuristicReasons = chat_safe_list($analysis['heuristics']['reasons'] ?? ($analysis['detection']['heuristic_reasons'] ?? []));

        $scanContext = [
            'checked_url' => $scan['url'],
            'detection' => [
                'final_verdict' => $scan['status'],
                'confidence_score' => floatval($scan['confidence_score']),
                'risk_level' => $scan['risk_level'],
            ],
            'suspicious_indicators' => array_values(array_unique(array_merge($heuristicReasons, chat_safe_list($analysis['detection']['suspicious_indicators'] ?? [])))),
            'extracted_features' => $features,
            'mitre_attack' => $mitre,
            'nist_actions' => [
                'containment' => $nistContainment,
                'eradication_recovery' => $nistRecovery,
                'post_incident' => $nistPostIncident,
            ],
            'user_advisory' => $scan['user_advisory_text'] ?? ($llm['user_advisory'] ?? ''),
        ];
    }
}

if (empty($scanContext) || !isset($scanContext['detection']) || !is_array($scanContext['detection'])) {
    $scanContext = [
        'checked_url' => '',
        'detection' => [
            'final_verdict' => 'general_question',
            'risk_level' => 'unknown',
            'confidence_score' => '',
        ],
        'assistant_scope' => 'General ShieldURL and cybersecurity guidance. Do not claim a URL was scanned unless scan context is provided.',
    ];
}

$apiStart = microtime(true);
$payload = json_encode([
    'scan_id' => $scanId > 0 ? strval($scanId) : null,
    'message' => $question,
    'user_question' => $question,
    'question' => $question,
    'assistant_response_style' => $assistantStyle,
    'scan_context' => $scanContext,
    'history' => array_slice($data['history'] ?? ($data['conversation'] ?? []), -6),
    'conversation' => array_slice($data['conversation'] ?? ($data['history'] ?? []), -6),
]);

if (!function_exists('curl_init')) {
    chat_json([
        'success' => false,
        'answer' => 'The assistant is temporarily unavailable, but the scan result remains valid. Please follow the recommended actions.',
        'used_scan_context' => true,
        'safety_notice' => 'Detection result was not modified by the LLM.',
        'message' => 'PHP cURL extension is not enabled.'
    ], 503);
}

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'http://127.0.0.1:8000/chat');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json', 'Accept: application/json']);
curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
curl_setopt($ch, CURLOPT_TIMEOUT, 75);
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curlErr = curl_error($ch);
curl_close($ch);

$latencyMs = intval(round((microtime(true) - $apiStart) * 1000));
$answerStatus = 'ok';
$api = is_string($response) ? json_decode($response, true) : null;

if (!is_array($api) || $httpCode < 200 || $httpCode >= 300) {
    $answerStatus = 'fallback';
    $api = [
        'answer' => 'The assistant is temporarily unavailable, but the scan result remains valid. Please follow the recommended actions.',
        'used_scan_context' => true,
        'safety_notice' => 'Detection result was not modified by the LLM.',
        'debug' => [
            'http_code' => $httpCode,
            'curl_error' => $curlErr,
        ],
    ];
}

try {
    if (!$conn) {
        $db = new Database();
        $conn = $db->getConnection();
    }
    $logStmt = $conn->prepare('
        INSERT INTO chat_history (user_id, scan_id, user_question, answer_status, llm_latency_ms)
        VALUES (?, ?, ?, ?, ?)
    ');
    if ($scanId > 0) {
        $logStmt->execute([
            $_SESSION['user_id'],
            $scanId,
            chat_redact_question($question),
            $answerStatus,
            $latencyMs,
        ]);
    }
} catch (Exception $e) {
    $api['debug']['chat_log_error'] = $e->getMessage();
}

chat_json([
    'success' => true,
    'answer' => strval($api['answer'] ?? 'The assistant is temporarily unavailable, but the scan result remains valid. Please follow the recommended actions.'),
    'used_scan_context' => (bool)($api['used_scan_context'] ?? true),
    'safety_notice' => strval($api['safety_notice'] ?? 'Detection result was not modified by the LLM.'),
    'latency_ms' => $latencyMs,
]);
