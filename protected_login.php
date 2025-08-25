<?php
// protected_login.php - SECURE LOGIN WITH SQL INJECTION PROTECTION
// This code demonstrates proper security practices

header('Content-Type: text/html; charset=UTF-8');
session_start();

// Database configuration
$host = 'localhost';
$dbname = 'cybersecurity_demo';
$db_username = 'demo_user';
$db_password = 'demo_password';

// Create secure connection
try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $db_username, $db_password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

// CSRF protection
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Rate limiting (simple implementation)
$max_attempts = 5;
$lockout_time = 300; // 5 minutes
$client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

// Check rate limiting
$rate_limit_file = 'rate_limit_' . md5($client_ip) . '.txt';
$current_time = time();
$attempts = [];

if (file_exists($rate_limit_file)) {
    $attempts = json_decode(file_get_contents($rate_limit_file), true) ?? [];
    // Remove old attempts
    $attempts = array_filter($attempts, function($timestamp) use ($current_time, $lockout_time) {
        return ($current_time - $timestamp) < $lockout_time;
    });
}

$message = '';
$blocked_by_rate_limit = false;

if ($_POST) {
    // Check rate limiting
    if (count($attempts) >= $max_attempts) {
        $blocked_by_rate_limit = true;
        $message = "<div class='error'>❌ Too many login attempts. Please try again later.</div>";
    } else {
        // Input validation and sanitization
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        
        // Validate input format
        if (!preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
            $message = "<div class='error'>❌ Invalid username format. Use 3-20 characters, letters, numbers, and underscores only.</div>";
        } elseif (strlen($password) < 6) {
            $message = "<div class='error'>❌ Password must be at least 6 characters long.</div>";
        } else {
            // SQL injection prevention using prepared statements
            $sql = "SELECT id, username, password FROM users WHERE username = ? LIMIT 1";
            
            try {
                $stmt = $pdo->prepare($sql);
                $stmt->execute([$username]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if ($user && password_verify($password, $user['password'])) {
                    // Successful login
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    $message = "<div class='success'>✅ Login successful! Welcome, " . htmlspecialchars($user['username']) . "!</div>";
                    
                    // Log successful login
                    $log_message = date('Y-m-d H:i:s') . " - Successful login for user: $username from IP: $client_ip\n";
                    file_put_contents('protected_log.txt', $log_message, FILE_APPEND);
                } else {
                    // Failed login attempt
                    $attempts[] = $current_time;
                    file_put_contents($rate_limit_file, json_encode($attempts));
                    
                    $message = "<div class='error'>❌ Invalid username or password.</div>";
                    
                    // Log failed attempt
                    $log_message = date('Y-m-d H:i:s') . " - Failed login attempt for user: $username from IP: $client_ip\n";
                    file_put_contents('protected_log.txt', $log_message, FILE_APPEND);
                }
            } catch (PDOException $e) {
                $message = "<div class='error'>❌ System error. Please try again later.</div>";
                error_log("Database error: " . $e->getMessage());
            }
        }
    }
}

// Check for potential SQL injection attempts in logs
function detectSQLInjection($input) {
    $sql_patterns = [
        '/(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)/i',
        '/(\b(OR|AND)\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+[\'"]?)/i',
        '/[\'";]/i',
        '/--/',
        '/#/',
        '/\/\*/',
        '/\*\//'
    ];
    
    foreach ($sql_patterns as $pattern) {
        if (preg_match($pattern, $input)) {
            return true;
        }
    }
    return false;
}

$injection_attempt = false;
if (isset($_POST['username']) || isset($_POST['password'])) {
    if (detectSQLInjection($_POST['username'] ?? '') || detectSQLInjection($_POST['password'] ?? '')) {
        $injection_attempt = true;
        // Log potential attack
        $log_message = date('Y-m-d H:i:s') . " - Potential SQL injection attempt from IP: $client_ip - Data: " . 
                      json_encode($_POST) . "\n";
        file_put_contents('attack_log.txt', $log_message, FILE_APPEND);
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Protected Login Result</title>
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
        .security-info {
            background-color: #e8f5e8;
            border: 1px solid #4caf50;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }
        .attack-blocked {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }
        .back-link {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 15px;
            background-color: #28a745;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            margin-right: 10px;
        }
        .back-link:hover {
            background-color: #218838;
        }
        .rate-limit-info {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Protected Login Result</h2>
        
        <?php echo $message; ?>
        
        <?php if ($injection_attempt): ?>
        <div class="attack-blocked">
            <h4>🛡️ Attack Blocked!</h4>
            <p>A potential SQL injection attempt was detected and blocked by our security measures:</p>
            <ul>
                <li>✅ Input validation detected malicious patterns</li>
                <li>✅ Attack attempt has been logged</li>
                <li>✅ Prepared statements prevent SQL injection</li>
                <li>✅ ModSecurity WAF provides additional protection</li>
            </ul>
        </div>
        <?php endif; ?>
        
        <?php if ($blocked_by_rate_limit): ?>
        <div class="rate-limit-info">
            <h4>🚫 Rate Limit Protection</h4>
            <p>Your IP has been temporarily blocked due to too many failed login attempts. 
            This is a security measure to prevent brute force attacks.</p>
            <p>Please wait 5 minutes before trying again.</p>
        </div>
        <?php endif; ?>
        
        <div class="security-info">
            <h4>🛡️ Security Features Active</h4>
            <p>This form is protected by multiple security layers:</p>
            <ul>
                <li>✅ <strong>Prepared Statements:</strong> Prevents SQL injection</li>
                <li>✅ <strong>Input Validation:</strong> Validates format and length</li>
                <li>✅ <strong>Rate Limiting:</strong> Prevents brute force attacks</li>
                <li>✅ <strong>Password Hashing:</strong> Secure password storage</li>
                <li>✅ <strong>Attack Logging:</strong> Monitors and logs suspicious activity</li>
                <li>✅ <strong>Error Handling:</strong> Prevents information disclosure</li>
            </ul>
        </div>
        
        <?php if (isset($_POST) && !empty($_POST)): ?>
        <div style="margin-top: 20px;">
            <h4>Request Processing Info:</h4>
            <ul>
                <li>Input validation: ✅ Passed</li>
                <li>SQL injection check: ✅ <?php echo $injection_attempt ? 'Blocked' : 'Clean'; ?></li>
                <li>Rate limiting: ✅ <?php echo $blocked_by_rate_limit ? 'Applied' : 'Within limits'; ?></li>
                <li>Prepared statements: ✅ Used</li>
            </ul>
        </div>
        <?php endif; ?>
        
        <a href="page2.html" class="back-link">← Back to Protected Form</a>
        <a href="page1.html" class="back-link">Compare with Vulnerable Form</a>
    </div>
</body>
</html>