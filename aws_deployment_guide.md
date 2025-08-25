# AWS Deployment Guide - Cybersecurity Attack Demo (Python/Flask)

This guide provides step-by-step instructions for deploying the Python/Flask cybersecurity attack demonstration on AWS EC2.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [EC2 Instance Setup](#ec2-instance-setup)  
3. [Python/Flask Installation](#python-flask-installation)
4. [Database Configuration](#database-configuration)
5. [Application Deployment](#application-deployment)
6. [Testing and Verification](#testing-and-verification)
7. [Security Considerations](#security-considerations)
8. [Troubleshooting](#troubleshooting)

## Prerequisites

Before starting, ensure you have:
- AWS account with EC2 access
- Basic knowledge of Linux command line and Python
- SSH client (PuTTY for Windows, Terminal for Mac/Linux)
- Git installed locally (for cloning this repository)

## EC2 Instance Setup

### Step 1: Launch EC2 Instance

1. **Login to AWS Console**
   - Navigate to EC2 Dashboard
   - Click "Launch Instance"

2. **Configure Instance**
   ```
   Name: cybersecurity-flask-demo
   Application and OS Images: Ubuntu Server 22.04 LTS (Free Tier)
   Instance Type: t2.micro (Free Tier)
   Key Pair: Create new or use existing
   ```

3. **Network Settings**
   - Create security group with following rules:
     - SSH (22): Your IP only
     - HTTP (5000): 0.0.0.0/0 (Flask default port)

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

## Python/Flask Installation

### Step 3: Install Required Packages

```bash
# Install Python and development tools (MySQL no longer required)
sudo apt install -y python3 python3-pip python3-venv git curl wget
sudo apt install -y build-essential python3-dev pkg-config

# Verify Python installation
python3 --version
pip3 --version
```

### Step 4: Setup Application Environment

```bash
# Create application directory
sudo mkdir -p /opt/cybersecurity_attack
sudo chown ubuntu:ubuntu /opt/cybersecurity_attack
cd /opt/cybersecurity_attack

# Clone the repository
git clone https://github.com/rahulrk03/cybersecurity_attack.git .

# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

# Test web server
curl http://localhost
```

## Database Configuration

### Step 5: Setup SQLite Database with Python Script

```bash
# Navigate to application directory
cd /opt/cybersecurity_attack
source venv/bin/activate

# Run the database setup script (no additional setup required for SQLite)
python3 setup_database.py

# The script will:
# - Create the cybersecurity_demo.db SQLite database file
# - Create necessary tables (users, login_attempts, security_events)
# - Insert sample data for testing
```
# - Create necessary tables (users, login_attempts, security_events)
# - Insert sample data for testing
```

## Application Deployment

### Step 7: Configure Flask Application

```bash
# Ensure you're in the application directory with venv activated
cd /opt/cybersecurity_attack
source venv/bin/activate

# Test the application locally first
python3 app.py
```

The Flask application will start on port 5000. You should see output like:
```
* Running on all addresses (0.0.0.0)
* Running on http://127.0.0.1:5000
* Running on http://[your-private-ip]:5000
```

### Step 8: Setup Production Service (Optional)

For production deployment, create a systemd service:

```bash
# Create service file
sudo nano /etc/systemd/system/cybersecurity-demo.service
```

Add the following content:

```ini
[Unit]
Description=Cybersecurity Demo Flask Application
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/cybersecurity_attack
ExecStart=/opt/cybersecurity_attack/venv/bin/python app.py
Restart=always
RestartSec=3
Environment=FLASK_ENV=production

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable cybersecurity-demo
sudo systemctl start cybersecurity-demo

# Check status
sudo systemctl status cybersecurity-demo
```

# Test configuration
sudo apache2ctl configtest

# Restart Apache
sudo systemctl restart apache2
```

## Testing and Verification

### Step 9: Test the Application

1. **Access the Flask application**
   ```
   http://YOUR_PUBLIC_IP:5000/              (Home page)
   http://YOUR_PUBLIC_IP:5000/vulnerable    (Vulnerable form)
   http://YOUR_PUBLIC_IP:5000/protected     (Protected form)
   ```

2. **Test SQL Injection on Vulnerable Form**
   - Navigate to: `http://YOUR_PUBLIC_IP:5000/vulnerable`
   - Username: `admin' OR '1'='1' --`
   - Password: `anything`
   - Should succeed and demonstrate the vulnerability

3. **Test Protection on Secured Form**
   - Navigate to: `http://YOUR_PUBLIC_IP:5000/protected`
   - Try the same SQL injection payload
   - Should be blocked by input validation

4. **Test Normal Login**
   - Use credentials: `demo` / `demo123`
   - Should work on both forms

### Step 10: Monitor Application Logs

```bash
# View application logs
cd /opt/cybersecurity_attack

# Check vulnerable endpoint logs
tail -f vulnerable_log.txt

# Check protected endpoint logs  
tail -f protected_log.txt

# Check attack logs
tail -f attack_log.txt
```

### Step 11: Run Automated Tests

```bash
# Run the test suite
cd /opt/cybersecurity_attack
source venv/bin/activate
python3 test_app.py
```

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

## Security Considerations

⚠️ **WARNING**: This setup includes intentionally vulnerable code for educational purposes.

**Production Security Measures:**

1. **Firewall Configuration**
   ```bash
   # Enable UFW firewall
   sudo ufw enable
   sudo ufw allow 22/tcp    # SSH
   sudo ufw allow 5000/tcp  # Flask application
   ```

2. **SSL/TLS Setup** (Recommended for production)
   ```bash
   # Install Nginx as reverse proxy for SSL termination
   sudo apt install nginx certbot python3-certbot-nginx
   
   # Get SSL certificate (requires domain name)
   sudo certbot --nginx -d your-domain.com
   ```

3. **Regular Updates**
   ```bash
   # Set up automatic security updates
   sudo apt install unattended-upgrades
   sudo dpkg-reconfigure unattended-upgrades
   ```

4. **Application Security**
   - Change default Flask secret key in production
   - Use environment variables for sensitive configuration
   - Implement proper logging and monitoring
   - Regular security assessments

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
   # Check if SQLite database file exists and is readable
   ls -la /opt/cybersecurity_attack/cybersecurity_demo.db
   
   # Recreate database if needed
   cd /opt/cybersecurity_attack
   python3 setup_database.py
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
# Note: No MySQL service to stop (using SQLite)

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