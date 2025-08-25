<?php
// password_generator.php
// Helper script to generate password hashes for the database

echo "=== Password Hash Generator ===\n\n";

$passwords = [
    'admin123',
    'user123', 
    'test123',
    'demo123',
    'guest123'
];

echo "Generated password hashes for database:\n\n";

foreach ($passwords as $password) {
    $hash = password_hash($password, PASSWORD_DEFAULT);
    echo "Password: $password\n";
    echo "Hash: $hash\n\n";
}

echo "=== SQL UPDATE Statements ===\n\n";

$users = [
    'admin' => 'admin123',
    'user' => 'user123',
    'test' => 'test123'
];

foreach ($users as $username => $password) {
    $hash = password_hash($password, PASSWORD_DEFAULT);
    echo "UPDATE users SET password = '$hash' WHERE username = '$username';\n";
}

echo "\n=== Verification Test ===\n\n";

// Test password verification
$test_password = 'admin123';
$test_hash = password_hash($test_password, PASSWORD_DEFAULT);

if (password_verify($test_password, $test_hash)) {
    echo "✅ Password verification test PASSED\n";
} else {
    echo "❌ Password verification test FAILED\n";
}

echo "\nThis script helps generate secure password hashes for the protected login system.\n";
echo "Run this script on your server to get the hashes, then update the database_setup.sql file.\n";
?>