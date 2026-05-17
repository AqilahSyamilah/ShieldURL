<?php

function audit_client_ip()
{
    $headers = [
        'HTTP_CF_CONNECTING_IP',
        'HTTP_X_REAL_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_CLIENT_IP',
        'REMOTE_ADDR',
    ];

    foreach ($headers as $header) {
        if (empty($_SERVER[$header])) {
            continue;
        }
        $parts = explode(',', $_SERVER[$header]);
        foreach ($parts as $part) {
            $ip = trim($part);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }

    return '';
}

function audit_country_from_ip($ip)
{
    if ($ip === '') {
        return 'Unknown';
    }

    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return 'Local/Private';
    }

    static $cache = [];
    if (isset($cache[$ip])) {
        return $cache[$ip];
    }

    $url = 'http://ip-api.com/json/' . rawurlencode($ip) . '?fields=status,country';
    $context = stream_context_create(['http' => ['timeout' => 2]]);
    $json = @file_get_contents($url, false, $context);
    if ($json === false) {
        $cache[$ip] = 'Unknown';
        return $cache[$ip];
    }

    $data = json_decode($json, true);
    $cache[$ip] = (($data['status'] ?? '') === 'success' && !empty($data['country'])) ? $data['country'] : 'Unknown';
    return $cache[$ip];
}

function audit_log($conn, $activityType, $activityDetails = '', $status = 'success', $context = [])
{
    try {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $userId = $context['user_id'] ?? ($_SESSION['user_id'] ?? null);
        $username = $context['username'] ?? ($_SESSION['username'] ?? null);
        $role = $context['role'] ?? ($_SESSION['role'] ?? null);
        $division = $context['division'] ?? null;

        if ($userId && (!$username || !$role || !$division)) {
            $stmt = $conn->prepare("SELECT username, role, department FROM users WHERE id=? LIMIT 1");
            $stmt->execute([$userId]);
            $user = $stmt->fetch();
            if ($user) {
                $username = $username ?: $user['username'];
                $role = $role ?: $user['role'];
                $division = $division ?: ($user['department'] ?: null);
            }
        }

        $ip = $context['ip_address'] ?? audit_client_ip();
        $country = $context['country'] ?? audit_country_from_ip($ip);
        $sessionId = $context['session_id'] ?? session_id();

        $stmt = $conn->prepare("
            INSERT INTO audit_logs
                (user_id, username, role, division, activity_type, activity_details, ip_address, country, status, session_id)
            VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        $stmt->execute([
            $userId ?: null,
            $username ?: 'unknown',
            $role ?: 'unknown',
            $division ?: 'Unassigned',
            $activityType,
            $activityDetails,
            $ip,
            $country,
            $status,
            $sessionId,
        ]);
    } catch (Throwable $e) {
        error_log('ShieldURL audit log failed: ' . $e->getMessage());
    }
}
