#!/usr/bin/env python3
"""
Database setup script for cybersecurity attack demonstration (Python version)
This script creates the database, tables, and sample data for the Flask application.
"""

import sqlite3
from werkzeug.security import generate_password_hash
import json
import os
from datetime import datetime

# Database configuration
DB_PATH = 'cybersecurity_demo.db'

def create_database():
    """Create SQLite database file"""
    try:
        # Remove existing database file if it exists
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
            print(f"✅ Existing database '{DB_PATH}' removed")
        
        # Create new database connection (file will be created automatically)
        connection = sqlite3.connect(DB_PATH)
        connection.close()
        print(f"✅ Database '{DB_PATH}' created successfully")
        return True
        
    except Exception as e:
        print(f"❌ Error creating database: {e}")
        return False

def setup_tables():
    """Create tables and insert sample data"""
    try:
        connection = sqlite3.connect(DB_PATH)
        cursor = connection.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(50) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                email VARCHAR(100),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME NULL
            )
        ''')
        print("✅ Users table created")
        
        # Create login_attempts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(50),
                ip_address VARCHAR(45),
                success INTEGER DEFAULT 0,
                attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_agent TEXT
            )
        ''')
        print("✅ Login attempts table created")
        
        # Create security_events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type VARCHAR(50),
                ip_address VARCHAR(45),
                description TEXT,
                severity TEXT DEFAULT 'MEDIUM' CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
                event_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                additional_data TEXT
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
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
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
            "INSERT INTO security_events (event_type, ip_address, description, severity) VALUES (?, ?, ?, ?)",
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
        
    except Exception as e:
        print(f"❌ Error setting up tables: {e}")
        return False
    finally:
        if connection:
            cursor.close()
            connection.close()
    
    return True

def main():
    """Main setup function"""
    print("🚀 Setting up cybersecurity demonstration database...")
    print("ℹ️  Using SQLite database (no setup required)")
    print()
    
    # Create database
    if not create_database():
        print("❌ Failed to create database")
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