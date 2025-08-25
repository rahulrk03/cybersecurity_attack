#!/usr/bin/env python3
"""
Database setup script for cybersecurity attack demonstration (Python version)
This script creates the database, tables, and sample data for the Flask application.
"""

import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash
import json
from datetime import datetime

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',  # Use root for setup
    'password': '',  # Set your MySQL root password here
}

DB_NAME = 'cybersecurity_demo'
DB_USER = 'demo_user'
DB_PASSWORD = 'demo_password'

def create_database_and_user():
    """Create database and user"""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        cursor = connection.cursor()
        
        # Create database
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
        print(f"✅ Database '{DB_NAME}' created successfully")
        
        # Create user and grant privileges
        cursor.execute(f"CREATE USER IF NOT EXISTS '{DB_USER}'@'localhost' IDENTIFIED BY '{DB_PASSWORD}'")
        cursor.execute(f"GRANT SELECT, INSERT, UPDATE ON {DB_NAME}.* TO '{DB_USER}'@'localhost'")
        cursor.execute("FLUSH PRIVILEGES")
        print(f"✅ User '{DB_USER}' created and permissions granted")
        
    except Error as e:
        print(f"❌ Error creating database/user: {e}")
        return False
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
    
    return True

def setup_tables():
    """Create tables and insert sample data"""
    db_config = DB_CONFIG.copy()
    db_config['database'] = DB_NAME
    db_config['user'] = DB_USER
    db_config['password'] = DB_PASSWORD
    
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                email VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL
            )
        ''')
        print("✅ Users table created")
        
        # Create login_attempts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50),
                ip_address VARCHAR(45),
                success BOOLEAN DEFAULT FALSE,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_agent TEXT
            )
        ''')
        print("✅ Login attempts table created")
        
        # Create security_events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INT AUTO_INCREMENT PRIMARY KEY,
                event_type VARCHAR(50),
                ip_address VARCHAR(45),
                description TEXT,
                severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'MEDIUM',
                event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                additional_data JSON
            )
        ''')
        print("✅ Security events table created")
        
        # Clear existing users
        cursor.execute("DELETE FROM users")
        
        # Insert sample users with both hashed and plain text passwords
        # Hashed passwords for the protected version
        admin_hash = generate_password_hash('admin123')
        user_hash = generate_password_hash('user123')
        test_hash = generate_password_hash('test123')
        
        sample_users = [
            ('admin', admin_hash, 'admin@example.com'),
            ('user', user_hash, 'user@example.com'), 
            ('test', test_hash, 'test@example.com'),
            # Plain text passwords for the vulnerable version (educational purposes)
            ('demo', 'demo123', 'demo@example.com'),
            ('guest', 'guest123', 'guest@example.com')
        ]
        
        cursor.executemany(
            "INSERT INTO users (username, password, email) VALUES (%s, %s, %s)",
            sample_users
        )
        print("✅ Sample users inserted")
        
        # Insert sample security events
        sample_events = [
            ('SQL_INJECTION_ATTEMPT', '192.168.1.100', 'Detected SQL injection in login form', 'HIGH'),
            ('BRUTE_FORCE_ATTEMPT', '10.0.0.50', 'Multiple failed login attempts detected', 'MEDIUM'),
            ('SUCCESSFUL_LOGIN', '192.168.1.10', 'User admin logged in successfully', 'LOW')
        ]
        
        cursor.executemany(
            "INSERT INTO security_events (event_type, ip_address, description, severity) VALUES (%s, %s, %s, %s)",
            sample_events
        )
        print("✅ Sample security events inserted")
        
        connection.commit()
        
        # Display created users
        cursor.execute("SELECT id, username, email FROM users")
        users = cursor.fetchall()
        print("\n📊 Created users:")
        for user in users:
            print(f"  - ID: {user[0]}, Username: {user[1]}, Email: {user[2]}")
        
        print(f"\n🔐 Credentials for testing:")
        print(f"  - admin/admin123 (hashed password)")
        print(f"  - user/user123 (hashed password)")
        print(f"  - test/test123 (hashed password)")
        print(f"  - demo/demo123 (plain text - for vulnerable demo)")
        print(f"  - guest/guest123 (plain text - for vulnerable demo)")
        
    except Error as e:
        print(f"❌ Error setting up tables: {e}")
        return False
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
    
    return True

def main():
    """Main setup function"""
    print("🚀 Setting up cybersecurity demonstration database...")
    print("⚠️  Make sure MySQL is running and you have root access")
    print()
    
    # Get MySQL root password from user
    import getpass
    global DB_CONFIG
    root_password = getpass.getpass("Enter MySQL root password (press Enter if no password): ")
    if root_password:
        DB_CONFIG['password'] = root_password
    
    # Create database and user
    if not create_database_and_user():
        print("❌ Failed to create database and user")
        return
    
    # Setup tables
    if not setup_tables():
        print("❌ Failed to setup tables")
        return
    
    print("\n✅ Database setup completed successfully!")
    print("\n🚀 You can now run the Flask application:")
    print("   python3 app.py")
    print("\n🌐 Access the application at:")
    print("   http://localhost:5000")

if __name__ == '__main__':
    main()