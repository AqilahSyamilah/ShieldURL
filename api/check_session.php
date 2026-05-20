<?php
session_start();
header('Content-Type: application/json');

if (!isset($_SESSION['user_id'])) {
    echo json_encode([
        "valid" => false,
        "message" => "Session has destroyed. Please login."
    ]);
    exit();
}

echo json_encode([
    "valid" => true
]);