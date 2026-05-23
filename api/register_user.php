<?php
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

header('Content-Type: application/json');

require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../shared/mailer.php';
require_once __DIR__ . '/../shared/audit.php';

function register_json($payload, $statusCode = 200)
{
    http_response_code($statusCode);
    echo json_encode($payload);
    exit();
}

$requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($requestMethod !== 'POST') {
    register_json(['success' => false, 'message' => 'Invalid request method'], 405);
}

if (!isset($_SESSION['user_id']) || ($_SESSION['role'] ?? '') !== 'admin') {
    register_json(['success' => false, 'message' => 'Unauthorized'], 403);
}

$input = json_decode(file_get_contents('php://input'), true) ?? [];

$required = ['full_name','email','phone','department','role'];
foreach ($required as $field) {
    if (!isset($input[$field]) || trim((string)$input[$field]) === '') {
        register_json(['success' => false, 'message' => "Field cannot be empty", 'field' => $field], 400);
    }
}

if (!filter_var($input['email'], FILTER_VALIDATE_EMAIL)) {
    register_json(['success' => false, 'message' => 'Invalid email'], 400);
}

if (!in_array($input['role'], ['admin','user'], true)) {
    register_json(['success' => false, 'message' => 'Invalid role'], 400);
}

$db = new Database();
$conn = $db->getConnection();

$email = trim($input['email']);
$username = trim($input['username'] ?? '');
if ($username === '') {
    $base = preg_replace('/[^a-zA-Z0-9_]/', '_', strstr($email, '@', true) ?: 'user');
    $base = trim($base, '_') ?: 'user';
    $username = substr($base, 0, 40);
    $candidate = $username;
    $suffix = 1;
    while (true) {
        $checkName = $conn->prepare("SELECT id FROM users WHERE username=? LIMIT 1");
        $checkName->execute([$candidate]);
        if (!$checkName->fetch()) {
            $username = $candidate;
            break;
        }
        $candidate = substr($base, 0, 35) . '_' . $suffix++;
    }
}

if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
    register_json(['success' => false, 'message' => 'Username can only contain letters, numbers, underscores'], 400);
}

$check = $conn->prepare("SELECT id FROM users WHERE username=? OR email=? LIMIT 1");
$check->execute([$username, $email]);
if ($check->fetch()) {
    register_json(['success' => false, 'message' => 'Username or email already exists'], 409);
}

function generate_temp_password($length = 16)
{
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*';
    $password = '';
    $max = strlen($alphabet) - 1;
    for ($i = 0; $i < $length; $i++) {
        $password .= $alphabet[random_int(0, $max)];
    }
    return $password;
}

function app_base_url()
{
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $base = rtrim(dirname(dirname($_SERVER['SCRIPT_NAME'] ?? '/ShieldURL/api/register_user.php')), '/\\');
    return $scheme . '://' . $host . ($base ? $base : '');
}

function send_welcome_email($to, $name, $username, $tempPassword)
{
    $loginLink = app_base_url() . '/auth/login.php';
    $subject = 'Your ShieldURL account is ready';
    $body = "Hello {$name},\n\n"
        . "A ShieldURL account has been created for you.\n\n"
        . "Login email/username: {$to} / {$username}\n"
        . "Temporary password: {$tempPassword}\n"
        . "Login link: {$loginLink}\n\n"
        . "After your first login, you must change this temporary password. You will then verify a 6-digit code sent to this email address before accessing the dashboard.\n\n"
        . "ShieldURL";
    return shieldurl_send_mail($to, $subject, $body);
}

$tempPassword = generate_temp_password();
$hashed = password_hash($tempPassword, PASSWORD_DEFAULT);

try {
    $stmt = $conn->prepare("
        INSERT INTO users (full_name, username, email, phone, department, role, password, is_active, account_status, force_password_change, mfa_required, mfa_configured, registered_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, TRUE, 'pending_first_login', TRUE, TRUE, FALSE, NOW())
    ");

    $stmt->execute([
        $input['full_name'],
        $username,
        $email,
        $input['phone'] ?? null,
        $input['department'] ?? null,
        $input['role'],
        $hashed
    ]);

    $emailSent = send_welcome_email($email, $input['full_name'], $username, $tempPassword);

    $activity = $conn->prepare("
        INSERT INTO user_activity (user_id, activity_type, description, ip_address)
        VALUES (?, 'user_registration', ?, ?)
    ");
    $desc = "Admin '{$_SESSION['username']}' registered new user '{$username}' with first-login password reset required";
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    $activity->execute([$_SESSION['user_id'], $desc, $ip]);
    audit_log($conn, 'admin_register_user', "Registered user '{$username}' ({$email}) with role '{$input['role']}'", 'success');

    register_json([
        'success' => true,
        'message' => $emailSent
            ? 'User registered successfully. A temporary password email was sent.'
            : 'User registered successfully. SMTP email is not configured, so the temporary password was written to the PHP error log.',
        'username' => $username,
        'account_status' => 'pending_first_login'
    ]);
} catch (PDOException $e) {
    error_log('register_user.php database error: ' . $e->getMessage());
    register_json(['success' => false, 'message' => 'Unable to register user'], 500);
}
