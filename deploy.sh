#!/bin/bash

# deploy.sh - Quick deployment script for Ubuntu/Debian systems
# This script automates the basic setup for the cybersecurity demonstration

set -e  # Exit on error

echo "🚀 Cybersecurity Attack Demo - Quick Deployment Script"
echo "========================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root. Please run as a regular user with sudo privileges."
   exit 1
fi

# Update system packages
print_status "Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install required packages
print_status "Installing Apache, PHP, MySQL, and ModSecurity..."
sudo apt install -y apache2 php php-mysql mysql-server git curl wget unzip
sudo apt install -y php-curl php-gd php-mbstring php-xml php-zip
sudo apt install -y libapache2-mod-security2 modsecurity-crs

# Enable Apache modules
print_status "Enabling Apache modules..."
sudo a2enmod rewrite ssl headers security2 unique_id

# Create web directory
print_status "Setting up web directory..."
sudo mkdir -p /var/www/html/cybersecurity_attack
sudo chown -R www-data:www-data /var/www/html/cybersecurity_attack
sudo chmod -R 755 /var/www/html/cybersecurity_attack

# Copy application files
print_status "Copying application files..."
if [ -f "page1.html" ]; then
    sudo cp *.html /var/www/html/cybersecurity_attack/
    sudo cp *.php /var/www/html/cybersecurity_attack/
    sudo chown -R www-data:www-data /var/www/html/cybersecurity_attack
    sudo chmod -R 644 /var/www/html/cybersecurity_attack/*
    sudo chmod 755 /var/www/html/cybersecurity_attack
    print_status "Application files copied successfully"
else
    print_warning "Application files not found in current directory"
    print_warning "Please ensure you're running this script from the project directory"
fi

# Configure Apache virtual host
print_status "Configuring Apache virtual host..."
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com/ || echo "localhost")

sudo tee /etc/apache2/sites-available/cybersecurity-demo.conf > /dev/null <<EOF
<VirtualHost *:80>
    ServerAdmin admin@example.com
    ServerName $PUBLIC_IP
    DocumentRoot /var/www/html/cybersecurity_attack
    
    <Directory /var/www/html/cybersecurity_attack>
        Options -Indexes +FollowSymLinks
        AllowOverride None
        Require all granted
        
        <Files "*.conf">
            Require all denied
        </Files>
        <Files "*.sql">
            Require all denied
        </Files>
        <Files "*.log">
            Require all denied
        </Files>
    </Directory>
    
    # Security headers
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    
    ErrorLog \${APACHE_LOG_DIR}/cybersecurity_demo_error.log
    CustomLog \${APACHE_LOG_DIR}/cybersecurity_demo_access.log combined
</VirtualHost>
EOF

# Enable site
sudo a2ensite cybersecurity-demo.conf
sudo a2dissite 000-default.conf

# Configure ModSecurity
print_status "Configuring ModSecurity..."
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

# Copy custom ModSecurity rules if available
if [ -f "modsecurity_rules.conf" ]; then
    sudo cp modsecurity_rules.conf /etc/apache2/conf-available/
    sudo a2enconf modsecurity_rules
    print_status "Custom ModSecurity rules installed"
fi

# Enable ModSecurity
sudo a2enconf modsecurity

# Test Apache configuration
print_status "Testing Apache configuration..."
if sudo apache2ctl configtest; then
    print_status "Apache configuration test passed"
else
    print_error "Apache configuration test failed"
    exit 1
fi

# Restart Apache
print_status "Restarting Apache..."
sudo systemctl restart apache2

# MySQL setup reminder
print_warning "========================================================="
print_warning "MANUAL STEPS REQUIRED:"
print_warning "1. Secure MySQL installation:"
print_warning "   sudo mysql_secure_installation"
print_warning ""
print_warning "2. Create database and user:"
print_warning "   sudo mysql -u root -p < database_setup.sql"
print_warning ""
print_warning "3. Update database credentials in PHP files:"
print_warning "   - Edit vulnerable_login.php"
print_warning "   - Edit protected_login.php"
print_warning ""
print_warning "4. Test the setup:"
print_warning "   http://$PUBLIC_IP/test_setup.php"
print_warning ""
print_warning "5. Access the applications:"
print_warning "   - Vulnerable: http://$PUBLIC_IP/page1.html"
print_warning "   - Protected:  http://$PUBLIC_IP/page2.html"
print_warning "========================================================="

print_status "Basic deployment completed!"
print_status "Please complete the manual steps above before testing."

# Create a simple status check
cat > /tmp/deployment_status.txt <<EOF
Cybersecurity Demo Deployment Status
====================================

Date: $(date)
Server IP: $PUBLIC_IP

Installed Components:
- Apache2: $(apache2 -v | head -n1)
- PHP: $(php -v | head -n1)
- MySQL: $(mysql --version)
- ModSecurity: $(dpkg -l | grep libapache2-mod-security2 | awk '{print $3}')

Next Steps:
1. Complete MySQL setup with database_setup.sql
2. Update database credentials in PHP files
3. Test with: http://$PUBLIC_IP/test_setup.php

URLs:
- Vulnerable: http://$PUBLIC_IP/page1.html
- Protected:  http://$PUBLIC_IP/page2.html
EOF

print_status "Deployment status saved to /tmp/deployment_status.txt"