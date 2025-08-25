#!/bin/bash

# deploy.sh - Python/Flask deployment script for Ubuntu/Debian systems
# This script automates the basic setup for the cybersecurity demonstration

set -e  # Exit on error

echo "🚀 Cybersecurity Attack Demo - Python/Flask Deployment Script"
echo "=============================================================="

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

# Install required packages for Python/Flask
print_status "Installing Python, MySQL, and required packages..."
sudo apt install -y python3 python3-pip python3-venv mysql-server git curl wget
sudo apt install -y build-essential python3-dev default-libmysqlclient-dev pkg-config

# Create application directory
print_status "Setting up application directory..."
APP_DIR="/opt/cybersecurity_attack"
sudo mkdir -p $APP_DIR
sudo chown $USER:$USER $APP_DIR

# Copy application files
print_status "Copying application files..."
if [ -f "app.py" ]; then
    cp app.py setup_database.py requirements.txt $APP_DIR/
    cp *.md $APP_DIR/ 2>/dev/null || true
    cp *.sql $APP_DIR/ 2>/dev/null || true
    cp test_app.py $APP_DIR/ 2>/dev/null || true
    print_status "Application files copied successfully"
else
    print_warning "app.py not found in current directory"
    print_warning "Please ensure you're running this script from the project directory"
    exit 1
fi

# Create Python virtual environment
print_status "Creating Python virtual environment..."
cd $APP_DIR
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
print_status "Installing Python dependencies..."
pip install -r requirements.txt

# Make scripts executable
chmod +x setup_database.py
chmod +x app.py

# Get public IP
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com/ || echo "localhost")

# MySQL setup reminder
print_warning "=============================================================="
print_warning "MANUAL STEPS REQUIRED:"
print_warning "1. Secure MySQL installation:"
print_warning "   sudo mysql_secure_installation"
print_warning ""
print_warning "2. Setup database (run from $APP_DIR):"
print_warning "   cd $APP_DIR"
print_warning "   source venv/bin/activate"
print_warning "   python3 setup_database.py"
print_warning ""
print_warning "3. Start the Flask application:"
print_warning "   python3 app.py"
print_warning ""
print_warning "4. Access the application:"
print_warning "   - Home: http://$PUBLIC_IP:5000/"
print_warning "   - Vulnerable: http://$PUBLIC_IP:5000/vulnerable"
print_warning "   - Protected: http://$PUBLIC_IP:5000/protected"
print_warning "=============================================================="

print_status "Python/Flask deployment completed!"
print_status "Please complete the manual steps above before testing."

# Create a simple status check
cat > /tmp/deployment_status.txt <<EOF
Cybersecurity Demo - Python/Flask Deployment Status
==================================================

Date: $(date)
Server IP: $PUBLIC_IP
Application Directory: $APP_DIR

Installed Components:
- Python: $(python3 --version)
- pip: $(pip --version)
- MySQL: $(mysql --version)

Application Structure:
- Flask app: $APP_DIR/app.py
- Database setup: $APP_DIR/setup_database.py
- Virtual environment: $APP_DIR/venv/

Next Steps:
1. Complete MySQL setup with setup_database.py
2. Start Flask application: python3 app.py
3. Test at: http://$PUBLIC_IP:5000/

URLs:
- Home: http://$PUBLIC_IP:5000/
- Vulnerable: http://$PUBLIC_IP:5000/vulnerable
- Protected: http://$PUBLIC_IP:5000/protected
EOF

print_status "Deployment status saved to /tmp/deployment_status.txt"