<?php
// hash_password.php - Save this in your project root
$password = 'admin123'; // Your desired password
$hashed_password = password_hash($password, PASSWORD_DEFAULT);
echo "Hashed Password: " . $hashed_password;
echo "\n\nSQL Insert:\n";
echo "INSERT INTO users (username, email, password) VALUES ('admin', 'admin@shieldurl.com', '" . $hashed_password . "');";
?>