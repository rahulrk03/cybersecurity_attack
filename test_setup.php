<?php
// test_setup.php
// Simple test script to verify the environment setup

echo "<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Setup Verification Test</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .success { color: green; }
        .error { color: red; }
        .warning { color: orange; }
        .test-section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Cybersecurity Demo - Setup Verification</h1>";

// Test 1: PHP Version
echo "<div class='test-section'>
    <h3>PHP Configuration</h3>";
echo "<p>PHP Version: " . phpversion() . "</p>";

if (version_compare(phpversion(), '7.4.0', '>=')) {
    echo "<p class='success'>✅ PHP version is compatible</p>";
} else {
    echo "<p class='error'>❌ PHP version too old (requires 7.4+)</p>";
}

// Test 2: Required Extensions
echo "<h4>Required PHP Extensions:</h4>";
$required_extensions = ['pdo', 'pdo_mysql', 'mysqli', 'curl'];
foreach ($required_extensions as $ext) {
    if (extension_loaded($ext)) {
        echo "<p class='success'>✅ $ext extension loaded</p>";
    } else {
        echo "<p class='error'>❌ $ext extension missing</p>";
    }
}
echo "</div>";

// Test 3: Database Connection
echo "<div class='test-section'>
    <h3>Database Connection Test</h3>";

$host = 'localhost';
$dbname = 'cybersecurity_demo';
$username = 'demo_user';
$password = 'demo_password';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    echo "<p class='success'>✅ Database connection successful</p>";
    
    // Test table existence
    $tables = ['users'];
    foreach ($tables as $table) {
        $stmt = $pdo->query("SHOW TABLES LIKE '$table'");
        if ($stmt->rowCount() > 0) {
            echo "<p class='success'>✅ Table '$table' exists</p>";
            
            // Count records
            $count_stmt = $pdo->query("SELECT COUNT(*) FROM $table");
            $count = $count_stmt->fetchColumn();
            echo "<p>Records in $table: $count</p>";
        } else {
            echo "<p class='error'>❌ Table '$table' missing</p>";
        }
    }
} catch (PDOException $e) {
    echo "<p class='error'>❌ Database connection failed: " . htmlspecialchars($e->getMessage()) . "</p>";
    echo "<p class='warning'>⚠️ Make sure to run database_setup.sql first</p>";
}
echo "</div>";

// Test 4: File Permissions
echo "<div class='test-section'>
    <h3>File Permissions Test</h3>";

$files_to_check = [
    'page1.html',
    'page2.html', 
    'vulnerable_login.php',
    'protected_login.php'
];

foreach ($files_to_check as $file) {
    if (file_exists($file)) {
        echo "<p class='success'>✅ $file exists</p>";
        if (is_readable($file)) {
            echo "<p class='success'>✅ $file is readable</p>";
        } else {
            echo "<p class='error'>❌ $file is not readable</p>";
        }
    } else {
        echo "<p class='error'>❌ $file missing</p>";
    }
}
echo "</div>";

// Test 5: Web Server Info
echo "<div class='test-section'>
    <h3>Web Server Information</h3>";
echo "<p>Server Software: " . ($_SERVER['SERVER_SOFTWARE'] ?? 'Unknown') . "</p>";
echo "<p>Document Root: " . ($_SERVER['DOCUMENT_ROOT'] ?? 'Unknown') . "</p>";
echo "<p>Server Name: " . ($_SERVER['SERVER_NAME'] ?? 'Unknown') . "</p>";
echo "<p>Server Port: " . ($_SERVER['SERVER_PORT'] ?? 'Unknown') . "</p>";

// Check for ModSecurity
if (function_exists('apache_get_modules')) {
    $modules = apache_get_modules();
    if (in_array('mod_security2', $modules)) {
        echo "<p class='success'>✅ ModSecurity module loaded</p>";
    } else {
        echo "<p class='warning'>⚠️ ModSecurity module not detected</p>";
    }
} else {
    echo "<p class='warning'>⚠️ Cannot check Apache modules (not running under Apache or function disabled)</p>";
}
echo "</div>";

// Test 6: Security Headers Test
echo "<div class='test-section'>
    <h3>Security Headers</h3>";
$headers = headers_list();
if (!empty($headers)) {
    echo "<p>Current headers:</p><ul>";
    foreach ($headers as $header) {
        echo "<li>" . htmlspecialchars($header) . "</li>";
    }
    echo "</ul>";
} else {
    echo "<p class='warning'>⚠️ No custom headers detected</p>";
}
echo "</div>";

echo "<div class='test-section'>
    <h3>Next Steps</h3>
    <p>If all tests pass, you can proceed to test the application:</p>
    <ul>
        <li><a href='page1.html'>Test Vulnerable Form (page1.html)</a></li>
        <li><a href='page2.html'>Test Protected Form (page2.html)</a></li>
    </ul>
    
    <h4>Common Issues:</h4>
    <ul>
        <li>If database connection fails: Run <code>mysql < database_setup.sql</code></li>
        <li>If files are missing: Ensure all files are uploaded to the web directory</li>
        <li>If ModSecurity is not loaded: Install and enable mod_security2</li>
        <li>If permissions are wrong: Run <code>sudo chown -R www-data:www-data /var/www/html/</code></li>
    </ul>
</div>";

echo "</body></html>";
?>