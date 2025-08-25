# Cybersecurity Attack Demonstration (Python/Flask)

A comprehensive demonstration of SQL injection vulnerabilities and their mitigation, designed for educational purposes and cybersecurity training. This project has been converted from PHP to Python using Flask for easier understanding and learning.

## 🎯 Project Overview

This project demonstrates the difference between vulnerable and secure web applications, specifically focusing on SQL injection attacks and their prevention. It includes:

- **Vulnerable login endpoint** (`/vulnerable`) - Intentionally exploitable via SQL injection
- **Protected login endpoint** (`/protected`) - Secured with multiple protection layers
- **Flask web application** - Easy-to-understand Python code for beginners
- **Comprehensive documentation** - For learning and implementation

## 🚨 Security Notice

⚠️ **WARNING**: This repository contains intentionally vulnerable code for educational purposes only. 

- **DO NOT** deploy in production environments
- **DO NOT** test on systems you don't own
- **USE ONLY** on your own test environments
- **ETHICAL USE** - For learning cybersecurity concepts only

## 📁 Repository Structure

```
cybersecurity_attack/
├── app.py                       # Main Flask application (Python)
├── setup_database.py            # Database setup script (Python)
├── test_app.py                  # Automated testing script
├── requirements.txt             # Python dependencies
├── PYTHON_GUIDE.md              # Quick start guide for beginners
├── database_setup.sql           # MySQL database setup script (legacy)
├── modsecurity_rules.conf       # ModSecurity WAF rules
├── apache_config.conf           # Apache virtual host configuration
├── aws_deployment_guide.md      # AWS deployment guide
├── deploy.sh                    # Automated deployment script
└── README.md                    # This file
```

## 🐍 Why Python?

This project has been converted from PHP to Python/Flask because:

- **Beginner-friendly**: Python has cleaner, more readable syntax
- **Educational value**: Easier to understand for new programmers
- **Industry standard**: Python is widely used in cybersecurity
- **Flask simplicity**: Minimal framework that's easy to learn
- **Better documentation**: Python code is more self-documenting

## 🎯 Learning Objectives

After completing this project, you will understand:

1. **SQL Injection Vulnerabilities**
   - How SQL injection attacks work
   - Common attack vectors and payloads
   - Impact of successful SQL injection

2. **Security Mitigation Techniques**
   - Prepared statements and parameterized queries
   - Input validation and sanitization
   - Rate limiting and CSRF protection

3. **Python Web Development**
   - Flask framework basics
   - Database connections with Python
   - Security best practices in Python

4. **Cybersecurity Fundamentals**
   - Attack detection and logging
   - Defense-in-depth strategies
   - Secure coding practices

## 🚀 Quick Start

### Prerequisites

1. **Python 3.7+** installed
2. **MySQL** server running
3. **Git** for cloning the repository

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/rahulrk03/cybersecurity_attack.git
   cd cybersecurity_attack
   ```

2. **Install Python dependencies**:
   ```bash
   pip3 install -r requirements.txt
   ```

3. **Set up the database**:
   ```bash
   python3 setup_database.py
   ```
   - Enter your MySQL root password when prompted
   - The script will create the database, user, and sample data

4. **Run the Flask application**:
   ```bash
   python3 app.py
   ```

5. **Access the application**:
   - Open your browser to `http://localhost:5000`
   - Navigate to the vulnerable or protected forms

## 🧪 Testing the Vulnerability

### SQL Injection Test Payloads

Try these on the **vulnerable form** (`http://localhost:5000/vulnerable`):

```sql
-- Authentication bypass
admin' OR '1'='1' --
admin' OR 1=1 #

-- Union-based injection
' UNION SELECT 1,username,password FROM users --

-- Boolean-based blind injection
admin' AND 1=1 --
admin' AND 1=2 --
```

### Expected Results

**Vulnerable Form (`/vulnerable`)**:
- ✅ SQL injection payloads should work
- ✅ Authentication bypass should succeed
- ✅ Error messages may reveal database structure

**Protected Form (`/protected`)**:
- ❌ SQL injection attempts should be blocked
- ❌ Input validation should prevent malicious input
- ❌ Prepared statements prevent database manipulation

## 🛡️ Security Features Implemented

### Vulnerable Form Protection: ❌ NONE
- Direct SQL query concatenation
- No input validation
- No prepared statements
- No rate limiting

### Protected Form Security: ✅ COMPREHENSIVE
- **Prepared Statements**: Prevents SQL injection
- **Input Validation**: Validates format and length
- **Rate Limiting**: Prevents brute force attacks
- **CSRF Protection**: Protects against cross-site requests
- **Attack Detection**: Identifies and logs malicious patterns
- **Error Handling**: Prevents information disclosure

## 🔍 Code Structure

### app.py - Main Application

The Flask application contains:

```python
# Vulnerable endpoint (educational)
@app.route('/vulnerable_login', methods=['POST'])
def vulnerable_login():
    # DELIBERATELY INSECURE CODE
    sql_query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    # Direct string concatenation - VULNERABLE!

# Protected endpoint (secure)
@app.route('/protected_login', methods=['POST'])
def protected_login():
    # SECURE CODE WITH MULTIPLE PROTECTIONS
    cursor.execute("SELECT id, username, password FROM users WHERE username = %s LIMIT 1", (username,))
    # Parameterized query - SECURE!
```

### Key Security Differences

| Feature | Vulnerable Version | Protected Version |
|---------|-------------------|-------------------|
| SQL Queries | String concatenation | Prepared statements |
| Input Validation | None | Regex validation |
| Rate Limiting | None | IP-based limiting |
| CSRF Protection | None | Token-based |
| Attack Logging | Basic | Comprehensive |
| Error Handling | Detailed errors | Generic messages |

## 📊 Monitoring and Logging

The application creates several log files:

```bash
# View attack attempts
tail -f vulnerable_log.txt

# View security events
tail -f protected_log.txt  

# View potential attacks
tail -f attack_log.txt
```

## 🎓 Educational Use Cases

This project is perfect for:

- **Cybersecurity training courses**
- **Python programming education**
- **Web application security workshops**
- **Penetration testing practice**
- **Security awareness training**

## 🔧 Customization

### Adding New Attack Vectors

1. **Modify the vulnerable endpoint** to introduce new vulnerabilities
2. **Update the protected endpoint** with corresponding protections
3. **Add detection patterns** in the `detect_sql_injection()` function

### Extending Protection

1. **Add more validation rules** in the protected login function
2. **Implement additional logging** for different attack types
3. **Add new security headers** and protections

## 📚 Additional Resources

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Flask Security Documentation](https://flask.palletsprojects.com/en/2.3.x/security/)
- [Python Security Best Practices](https://python.org/dev/security/)
- [MySQL Connector Python Documentation](https://dev.mysql.com/doc/connector-python/en/)

## 🐛 Troubleshooting

### Common Issues

1. **Database Connection Error**:
   ```bash
   # Check MySQL is running
   sudo systemctl status mysql
   
   # Verify credentials in setup_database.py
   ```

2. **Permission Denied**:
   ```bash
   # Ensure proper file permissions
   chmod +x setup_database.py
   chmod +x app.py
   ```

3. **Module Not Found**:
   ```bash
   # Reinstall dependencies
   pip3 install -r requirements.txt
   ```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add appropriate tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚖️ Disclaimer

This software is provided for educational purposes only. The authors are not responsible for any misuse of this software. Users must ensure they have proper authorization before testing on any systems.

## 📧 Contact

For questions or support:
- Create an issue in this repository
- Review the troubleshooting section above

---

**Remember**: Always practice ethical hacking and responsible disclosure!

## 🆚 PHP vs Python Comparison

| Aspect | PHP Version | Python Version |
|--------|-------------|----------------|
| Syntax | `<?php ... ?>` | Clean Python syntax |
| Database | `$pdo->query($sql)` | `cursor.execute(sql, params)` |
| Variables | `$username` | `username` |
| Arrays | `$_POST['field']` | `request.form.get('field')` |
| Learning Curve | Steeper for beginners | Gentler for new programmers |
| Security Libraries | Built-in PDO | SQLAlchemy, Werkzeug |

The Python version maintains all the security features and educational value while being more accessible to newcomers to programming.