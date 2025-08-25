# AWS Deployment Guide - Cybersecurity Attack Demo

This guide provides step-by-step instructions for deploying the cybersecurity attack demonstration on AWS EC2.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [EC2 Instance Setup](#ec2-instance-setup)
3. [Software Installation](#software-installation)
4. [Database Configuration](#database-configuration)
5. [Web Server Configuration](#web-server-configuration)
6. [ModSecurity WAF Setup](#modsecurity-waf-setup)
7. [Application Deployment](#application-deployment)
8. [Testing and Verification](#testing-and-verification)
9. [Security Considerations](#security-considerations)
10. [Troubleshooting](#troubleshooting)

## Prerequisites

Before starting, ensure you have:
- AWS account with EC2 access
- Basic knowledge of Linux command line
- SSH client (PuTTY for Windows, Terminal for Mac/Linux)
- Git installed locally (for cloning this repository)

## EC2 Instance Setup

### Step 1: Launch EC2 Instance

1. **Login to AWS Console**
   - Navigate to EC2 Dashboard
   - Click "Launch Instance"

2. **Configure Instance**
   ```
   Name: cybersecurity-demo
   Application and OS Images: Ubuntu Server 22.04 LTS (Free Tier)
   Instance Type: t2.micro (Free Tier)
   Key Pair: Create new or use existing
   ```

3. **Network Settings**
   - Create security group with following rules:
     - SSH (22): Your IP only
     - HTTP (80): 0.0.0.0/0
     - HTTPS (443): 0.0.0.0/0 (optional)
     - MySQL (3306): Security group only (for internal access)

4. **Storage**
   - 8 GB gp2 (Free Tier eligible)

5. **Launch Instance**
   - Review and launch
   - Note down the public IP address

### Step 2: Connect to Instance

```bash
# Connect via SSH (replace with your key and IP)
ssh -i your-key.pem ubuntu@YOUR_PUBLIC_IP

# Update system packages
sudo apt update && sudo apt upgrade -y
```

## Software Installation

### Step 3: Install Required Packages

```bash
# Install Apache, PHP, MySQL, and development tools
sudo apt install -y apache2 php php-mysql mysql-server git curl wget unzip

# Install additional PHP extensions
sudo apt install -y php-curl php-gd php-mbstring php-xml php-zip

# Install ModSecurity and dependencies
sudo apt install -y libapache2-mod-security2 modsecurity-crs

# Enable Apache modules
sudo a2enmod rewrite
sudo a2enmod ssl
sudo a2enmod headers
sudo a2enmod security2
sudo a2enmod unique_id

# Restart Apache
sudo systemctl restart apache2
```

### Step 4: Verify Installation

```bash
# Check Apache status
sudo systemctl status apache2

# Check PHP version
php -v

# Check MySQL status
sudo systemctl status mysql

# Test web server
curl http://localhost
```

## Database Configuration

### Step 5: Secure MySQL Installation

```bash
# Run MySQL security script
sudo mysql_secure_installation

# Follow prompts:
# - Set root password: YES (choose strong password)
# - Remove anonymous users: YES
# - Disallow root login remotely: YES
# - Remove test database: YES
# - Reload privilege tables: YES
```

### Step 6: Create Database and User

```bash
# Login to MySQL as root
sudo mysql -u root -p

# Execute the following SQL commands:
```

```sql
-- Create database
CREATE DATABASE cybersecurity_demo;

-- Create demo user
CREATE USER 'demo_user'@'localhost' IDENTIFIED BY 'StrongPassword123!';

-- Grant privileges
GRANT SELECT, INSERT, UPDATE ON cybersecurity_demo.* TO 'demo_user'@'localhost';
FLUSH PRIVILEGES;

-- Use the database
USE cybersecurity_demo;

-- Create users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert test users
INSERT INTO users (username, password, email) VALUES 
('admin', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin@example.com'),
('demo', 'demo123', 'demo@example.com'),
('guest', 'guest123', 'guest@example.com');

-- Exit MySQL
EXIT;
```

## Web Server Configuration

### Step 7: Configure Apache Virtual Host

```bash
# Create document root
sudo mkdir -p /var/www/html/cybersecurity_attack

# Set permissions
sudo chown -R www-data:www-data /var/www/html/cybersecurity_attack
sudo chmod -R 755 /var/www/html/cybersecurity_attack

# Create virtual host configuration
sudo nano /etc/apache2/sites-available/cybersecurity-demo.conf
```

Add the following configuration:

```apache
<VirtualHost *:80>
    ServerAdmin admin@example.com
    ServerName YOUR_PUBLIC_IP
    DocumentRoot /var/www/html/cybersecurity_attack
    
    <Directory /var/www/html/cybersecurity_attack>
        Options -Indexes +FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
    
    # Security headers
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    
    ErrorLog ${APACHE_LOG_DIR}/cybersecurity_demo_error.log
    CustomLog ${APACHE_LOG_DIR}/cybersecurity_demo_access.log combined
</VirtualHost>
```

```bash
# Enable site and disable default
sudo a2ensite cybersecurity-demo.conf
sudo a2dissite 000-default.conf

# Test configuration
sudo apache2ctl configtest

# Restart Apache
sudo systemctl restart apache2
```

## ModSecurity WAF Setup

### Step 8: Configure ModSecurity

```bash
# Copy ModSecurity configuration
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf

# Edit ModSecurity configuration
sudo nano /etc/modsecurity/modsecurity.conf
```

Modify the following settings:

```
SecRuleEngine On
SecAuditEngine RelevantOnly
SecAuditLogParts ABDEFHIJZ
SecAuditLogType Serial
SecAuditLog /var/log/apache2/modsec_audit.log
```

### Step 9: Configure OWASP Core Rule Set

```bash
# Enable OWASP CRS
sudo ln -s /usr/share/modsecurity-crs /etc/apache2/conf-available/

# Create custom rules file
sudo nano /etc/apache2/conf-available/modsecurity-custom.conf
```

Add custom rules from the `modsecurity_rules.conf` file in this repository.

```bash
# Enable ModSecurity configuration
sudo a2enconf modsecurity
sudo a2enconf modsecurity-custom

# Test and restart Apache
sudo apache2ctl configtest
sudo systemctl restart apache2
```

## Application Deployment

### Step 10: Deploy Application Files

```bash
# Clone the repository
cd /tmp
git clone https://github.com/rahulrk03/cybersecurity_attack.git

# Copy files to web directory
sudo cp /tmp/cybersecurity_attack/*.html /var/www/html/cybersecurity_attack/
sudo cp /tmp/cybersecurity_attack/*.php /var/www/html/cybersecurity_attack/

# Set proper permissions
sudo chown -R www-data:www-data /var/www/html/cybersecurity_attack
sudo chmod -R 644 /var/www/html/cybersecurity_attack/*
sudo chmod 755 /var/www/html/cybersecurity_attack

# Create logs directory
sudo mkdir -p /var/www/html/cybersecurity_attack/logs
sudo chown www-data:www-data /var/www/html/cybersecurity_attack/logs
sudo chmod 755 /var/www/html/cybersecurity_attack/logs
```

### Step 11: Update Database Configuration

```bash
# Edit PHP files to update database credentials
sudo nano /var/www/html/cybersecurity_attack/vulnerable_login.php
sudo nano /var/www/html/cybersecurity_attack/protected_login.php
```

Update the database configuration in both files:

```php
$host = 'localhost';
$dbname = 'cybersecurity_demo';
$db_username = 'demo_user';
$db_password = 'StrongPassword123!';  // Use your actual password
```

## Testing and Verification

### Step 12: Test the Application

1. **Access the application**
   ```
   http://YOUR_PUBLIC_IP/page1.html  (Vulnerable form)
   http://YOUR_PUBLIC_IP/page2.html  (Protected form)
   ```

2. **Test SQL Injection on Vulnerable Form**
   - Username: `admin' OR '1'='1' --`
   - Password: `anything`
   - Should succeed and show vulnerability

3. **Test SQL Injection on Protected Form**
   - Same payload should be blocked by ModSecurity
   - Check logs: `sudo tail -f /var/log/apache2/modsec_audit.log`

4. **Test Normal Login**
   - Username: `demo`
   - Password: `demo123`
   - Should work on both forms

### Step 13: Monitor Logs

```bash
# Monitor Apache access logs
sudo tail -f /var/log/apache2/cybersecurity_demo_access.log

# Monitor Apache error logs
sudo tail -f /var/log/apache2/cybersecurity_demo_error.log

# Monitor ModSecurity audit logs
sudo tail -f /var/log/apache2/modsec_audit.log

# Monitor PHP errors
sudo tail -f /var/log/apache2/php_errors.log
```

## Security Considerations

### Important Security Notes

⚠️ **WARNING**: This setup includes intentionally vulnerable code for educational purposes.

**Production Security Measures:**

1. **Firewall Configuration**
   ```bash
   # Enable UFW firewall
   sudo ufw enable
   sudo ufw allow 22/tcp    # SSH
   sudo ufw allow 80/tcp    # HTTP
   sudo ufw allow 443/tcp   # HTTPS
   ```

2. **SSL/TLS Setup** (Recommended for production)
   ```bash
   # Install Certbot for Let's Encrypt
   sudo apt install certbot python3-certbot-apache
   
   # Get SSL certificate (requires domain name)
   sudo certbot --apache -d your-domain.com
   ```

3. **Regular Updates**
   ```bash
   # Set up automatic security updates
   sudo apt install unattended-upgrades
   sudo dpkg-reconfigure unattended-upgrades
   ```

4. **Backup Strategy**
   - Regular database backups
   - Configuration file backups
   - Log rotation setup

## Troubleshooting

### Common Issues and Solutions

1. **Apache won't start**
   ```bash
   sudo apache2ctl configtest
   sudo systemctl status apache2
   sudo journalctl -u apache2
   ```

2. **ModSecurity blocking legitimate requests**
   ```bash
   # Check ModSecurity logs
   sudo tail -f /var/log/apache2/modsec_audit.log
   
   # Temporarily disable specific rules
   sudo nano /etc/apache2/conf-available/modsecurity-custom.conf
   ```

3. **Database connection issues**
   ```bash
   # Test MySQL connection
   mysql -u demo_user -p cybersecurity_demo
   
   # Check MySQL status
   sudo systemctl status mysql
   ```

4. **Permission issues**
   ```bash
   # Fix web directory permissions
   sudo chown -R www-data:www-data /var/www/html/cybersecurity_attack
   sudo chmod -R 755 /var/www/html/cybersecurity_attack
   ```

5. **PHP errors**
   ```bash
   # Enable PHP error reporting (development only)
   sudo nano /etc/php/8.1/apache2/php.ini
   # Set: display_errors = On, log_errors = On
   sudo systemctl restart apache2
   ```

## Final URLs

After successful deployment, you should have:

- **Vulnerable form**: `http://YOUR_PUBLIC_IP/page1.html`
- **Protected form**: `http://YOUR_PUBLIC_IP/page2.html`

## Cleanup

When you're done with the demonstration:

```bash
# Stop services
sudo systemctl stop apache2
sudo systemctl stop mysql

# In AWS Console, terminate the EC2 instance to avoid charges
```

## Support

For issues with this deployment:
1. Check the troubleshooting section above
2. Review Apache and ModSecurity logs
3. Verify all configuration files are correct
4. Ensure security group rules allow HTTP traffic

---

**Note**: This setup is for educational purposes only. Never deploy vulnerable code in production environments.