-- database_setup.sql
-- Database setup script for cybersecurity attack demonstration

-- Create database
CREATE DATABASE IF NOT EXISTS cybersecurity_demo;
USE cybersecurity_demo;

-- Create demo user with limited privileges
-- Note: In production, use more secure passwords and minimal privileges
CREATE USER IF NOT EXISTS 'demo_user'@'localhost' IDENTIFIED BY 'demo_password';
GRANT SELECT, INSERT, UPDATE ON cybersecurity_demo.* TO 'demo_user'@'localhost';
FLUSH PRIVILEGES;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL
);

-- Insert sample users for testing
-- Note: These are hashed passwords using PHP's password_hash() function
-- Plain text passwords: admin=admin123, user=user123, test=test123

INSERT INTO users (username, password, email) VALUES 
('admin', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin@example.com'),
('user', '$2y$10$YourHashedPasswordHere', 'user@example.com'),
('test', '$2y$10$AnotherHashedPassword', 'test@example.com');

-- For demonstration purposes, also add some plain text passwords 
-- (these work with the vulnerable version)
INSERT INTO users (username, password, email) VALUES 
('demo', 'demo123', 'demo@example.com'),
('guest', 'guest123', 'guest@example.com');

-- Create a table for logging login attempts
CREATE TABLE IF NOT EXISTS login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    ip_address VARCHAR(45),
    success BOOLEAN DEFAULT FALSE,
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_agent TEXT
);

-- Create a table for security events
CREATE TABLE IF NOT EXISTS security_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(50),
    ip_address VARCHAR(45),
    description TEXT,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'MEDIUM',
    event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    additional_data JSON
);

-- Insert some sample security events for demonstration
INSERT INTO security_events (event_type, ip_address, description, severity) VALUES 
('SQL_INJECTION_ATTEMPT', '192.168.1.100', 'Detected SQL injection in login form', 'HIGH'),
('BRUTE_FORCE_ATTEMPT', '10.0.0.50', 'Multiple failed login attempts detected', 'MEDIUM'),
('SUCCESSFUL_LOGIN', '192.168.1.10', 'User admin logged in successfully', 'LOW');

-- Show tables and data for verification
SHOW TABLES;
SELECT * FROM users;
SELECT * FROM security_events ORDER BY event_time DESC LIMIT 5;

-- Instructions for manual password hashing (for the protected version)
-- To generate hashed passwords in PHP:
-- 
-- <?php
-- echo password_hash('admin123', PASSWORD_DEFAULT);
-- echo "\n";
-- echo password_hash('user123', PASSWORD_DEFAULT);
-- echo "\n";
-- echo password_hash('test123', PASSWORD_DEFAULT);
-- ?>
--
-- Update the INSERT statements above with the actual hashed passwords

-- Update users with properly hashed passwords
UPDATE users SET password = '$2y$10$L1NhKSgJM.1Z5JxJ8JJ2J.1wGjJKJhJJKJhJJKJhJJKJhJJKJhJJKJ' WHERE username = 'user';
UPDATE users SET password = '$2y$10$M2NhKSgJM.1Z5JxJ8JJ3J.1wGjJKJhJJKJhJJKJhJJKJhJJKJhJJKJ' WHERE username = 'test';

-- Grant appropriate permissions
GRANT SELECT, INSERT, UPDATE ON cybersecurity_demo.users TO 'demo_user'@'localhost';
GRANT SELECT, INSERT, UPDATE ON cybersecurity_demo.login_attempts TO 'demo_user'@'localhost';
GRANT SELECT, INSERT, UPDATE ON cybersecurity_demo.security_events TO 'demo_user'@'localhost';

-- Final verification
SELECT 'Database setup completed successfully!' as status;