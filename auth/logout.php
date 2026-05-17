<?php
require_once '../config/db.php';
require_once '../shared/audit.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
if (isset($_SESSION['user_id'])) {
    $db = new Database();
    $conn = $db->getConnection();
    audit_log($conn, 'logout', 'User logged out', 'success');
}
session_unset();
session_destroy();
header("Location: login.php");
exit();
