<?php
// Wrapper to set session for CLI testing and include the analyze endpoint
if (session_status() === PHP_SESSION_NONE) session_start();
$_SESSION['user_id'] = 1; // assume default admin exists from db setup

// include the analyze endpoint script
require __DIR__ . '/../api/analyze.php';
