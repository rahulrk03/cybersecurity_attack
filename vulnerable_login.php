<?php
// vulnerable_login.php - DELIBERATELY VULNERABLE TO SQL INJECTION
// WARNING: This code is intentionally insecure for educational purposes only!
// NEVER use this code in production environments.

header('Content-Type: text/html; charset=UTF-8');

// Database configuration
$host = 'localhost';
$dbname = 'cybersecurity_demo';
$db_username = 'demo_user';
$db_password = 'demo_password';

// Create connection
try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $db_username, $db_password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

// Process login attempt
$message = '';
$attack_detected = false;

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    // VULNERABLE CODE: Direct string concatenation without sanitization
    // This allows SQL injection attacks
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    
    try {
        $result = $pdo->query($sql);
        $user = $result->fetch(PDO::FETCH_ASSOC);
        
        if ($user) {
            $message = "<div class='success'>✅ Login successful! Welcome, " . htmlspecialchars($user['username']) . "!</div>";
            
            // If more than one row returned, it might be an injection attack
            if ($result->rowCount() > 1) {
                $attack_detected = true;
                $message .= "<div class='warning'>⚠️ SQL Injection detected! Multiple users returned.</div>";
            }
        } else {
            $message = "<div class='error'>❌ Invalid username or password.</div>";
        }
    } catch (PDOException $e) {
        $message = "<div class='error'>❌ Database error: " . htmlspecialchars($e->getMessage()) . "</div>";
        $attack_detected = true;
    }
    
    // Log the attempted query for demonstration
    $log_message = date('Y-m-d H:i:s') . " - Executed query: $sql\n";
    file_put_contents('vulnerable_log.txt', $log_message, FILE_APPEND);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerable Login Result</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 600px;
            margin: 50px auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .success {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            padding: 12px;
            border-radius: 4px;
            margin: 10px 0;
        }
        .error {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            padding: 12px;
            border-radius: 4px;
            margin: 10px 0;
        }
        .warning {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 12px;
            border-radius: 4px;
            margin: 10px 0;
        }
        .query-display {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            padding: 15px;
            border-radius: 4px;
            font-family: monospace;
            margin: 15px 0;
            overflow-x: auto;
        }
        .back-link {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 15px;
            background-color: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 4px;
        }
        .back-link:hover {
            background-color: #0056b3;
        }
        .vulnerability-info {
            background-color: #ffebee;
            border: 1px solid #f44336;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Vulnerable Login Result</h2>
        
        <?php echo $message; ?>
        
        <?php if ($attack_detected): ?>
        <div class="vulnerability-info">
            <h4>🚨 Vulnerability Demonstration</h4>
            <p>This page successfully demonstrates a SQL injection vulnerability. 
            The attack was executed because:</p>
            <ul>
                <li>User input is directly concatenated into the SQL query</li>
                <li>No input validation or sanitization is performed</li>
                <li>No prepared statements are used</li>
                <li>No Web Application Firewall (WAF) protection</li>
            </ul>
        </div>
        <?php endif; ?>
        
        <h4>Executed SQL Query:</h4>
        <div class="query-display">
            <?php echo htmlspecialchars($sql ?? 'No query executed'); ?>
        </div>
        
        <div style="margin-top: 20px;">
            <p><strong>Submitted Data:</strong></p>
            <ul>
                <li>Username: <code><?php echo htmlspecialchars($username ?? ''); ?></code></li>
                <li>Password: <code><?php echo htmlspecialchars($password ?? ''); ?></code></li>
            </ul>
        </div>
        
        <a href="page1.html" class="back-link">← Back to Vulnerable Form</a>
        <a href="page2.html" class="back-link">Try Protected Form →</a>
    </div>
</body>
</html>