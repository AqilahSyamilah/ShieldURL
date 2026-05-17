<?php
session_start();
require_once '../config/db.php';
require_once '../shared/audit.php';

// Ensure user is logged in
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit();
}

// Ensure user is admin
if ($_SESSION['role'] !== 'admin') {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Forbidden: Admins only']);
    exit();
}

// Get POST data
$data = json_decode(file_get_contents("php://input"), true);
$userIdToDelete = $data['id'] ?? null;

if (!$userIdToDelete) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'User ID required']);
    exit();
}

// Prevent self-deletion
if ($userIdToDelete == $_SESSION['user_id']) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Cannot delete your own account']);
    exit();
}

try {
    $db = new Database();
    $conn = $db->getConnection();

    // Check if user exists
    $stmt = $conn->prepare("SELECT id, username, role, department FROM users WHERE id = :id");
    $stmt->execute([':id' => $userIdToDelete]);
    $targetUser = $stmt->fetch();
    if (!$targetUser) {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'User not found']);
        exit();
    }

    // Delete user (Cascades to logs based on DB schema)
    $stmt = $conn->prepare("DELETE FROM users WHERE id = :id");
    $stmt->execute([':id' => $userIdToDelete]);
    audit_log($conn, 'admin_disable_user', "Deleted/disabled user '{$targetUser['username']}' (ID {$targetUser['id']})", 'success');

    echo json_encode(['success' => true, 'message' => 'User deleted successfully']);

} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
}
?>
