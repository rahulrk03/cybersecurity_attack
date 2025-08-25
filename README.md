# Cybersecurity Attack Demonstration

A comprehensive demonstration of SQL injection vulnerabilities and their mitigation using ModSecurity WAF, designed for educational purposes and cybersecurity training.

## 🎯 Project Overview

This project demonstrates the difference between vulnerable and secure web applications, specifically focusing on SQL injection attacks and their prevention. It includes:

- **Vulnerable login form** (`page1.html`) - Intentionally exploitable via SQL injection
- **Protected login form** (`page2.html`) - Secured with multiple protection layers
- **Complete AWS deployment guide** - Step-by-step instructions for EC2 setup
- **ModSecurity WAF configuration** - Web Application Firewall rules for protection
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
├── page1.html                  # Vulnerable login form
├── page2.html                  # Protected login form
├── vulnerable_login.php        # Backend with SQL injection vulnerability
├── protected_login.php         # Secure backend with protection
├── database_setup.sql          # MySQL database setup script
├── modsecurity_rules.conf      # Custom ModSecurity WAF rules
├── apache_config.conf          # Apache virtual host configuration
├── aws_deployment_guide.md     # Complete AWS deployment guide
└── README.md                   # This file
```

## 🎯 Learning Objectives

After completing this project, you will understand:

1. **SQL Injection Vulnerabilities**
   - How SQL injection attacks work
   - Common attack vectors and payloads
   - Impact of successful SQL injection

2. **Security Mitigation Techniques**
   - Prepared statements and parameterized queries
   - Input validation and sanitization
   - Web Application Firewall (WAF) protection

3. **AWS Deployment Skills**
   - EC2 instance configuration
   - Apache web server setup
   - MySQL database configuration
   - Security group management

4. **ModSecurity WAF Configuration**
   - OWASP Core Rule Set (CRS)
   - Custom rule creation
   - Log analysis and monitoring

## 🚀 Quick Start

### Option 1: AWS Deployment (Recommended)

1. **Follow the complete deployment guide**: [`aws_deployment_guide.md`](aws_deployment_guide.md)
2. **Access your deployed application**:
   - Vulnerable: `http://YOUR_EC2_IP/page1.html`
   - Protected: `http://YOUR_EC2_IP/page2.html`

### Option 2: Local Development

1. **Clone the repository**:
   ```bash
   git clone https://github.com/rahulrk03/cybersecurity_attack.git
   cd cybersecurity_attack
   ```

2. **Set up LAMP stack** (Linux, Apache, MySQL, PHP)

3. **Import database**:
   ```bash
   mysql -u root -p < database_setup.sql
   ```

4. **Configure Apache** using `apache_config.conf`

5. **Set up ModSecurity** using `modsecurity_rules.conf`

## 🧪 Testing the Vulnerability

### SQL Injection Test Payloads

Try these on the **vulnerable form** (`page1.html`):

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

**Vulnerable Form (page1.html)**:
- ✅ SQL injection payloads should work
- ✅ Authentication bypass should succeed
- ✅ Error messages may reveal database structure

**Protected Form (page2.html)**:
- ❌ SQL injection attempts should be blocked
- ❌ ModSecurity WAF should trigger alerts
- ❌ Input validation should prevent malicious input

## 🛡️ Security Features Implemented

### Vulnerable Form Protection: ❌ NONE
- Direct SQL query concatenation
- No input validation
- No prepared statements
- No WAF protection

### Protected Form Security: ✅ COMPREHENSIVE
- **Prepared Statements**: Prevents SQL injection
- **Input Validation**: Validates format and length
- **ModSecurity WAF**: Blocks malicious requests
- **Rate Limiting**: Prevents brute force attacks
- **CSRF Protection**: Protects against cross-site requests
- **Security Headers**: XSS, clickjacking protection
- **Error Handling**: Prevents information disclosure

## 📊 Monitoring and Logging

The application includes comprehensive logging:

```bash
# Application logs
tail -f /var/log/apache2/cybersecurity_demo_access.log
tail -f /var/log/apache2/cybersecurity_demo_error.log

# ModSecurity WAF logs
tail -f /var/log/apache2/modsec_audit.log

# Attack attempt logs
tail -f /var/www/html/cybersecurity_attack/logs/attack_log.txt
```

## 🎓 Educational Use Cases

This project is perfect for:

- **Cybersecurity training courses**
- **Penetration testing practice**
- **Web application security workshops**
- **DevSecOps demonstrations**
- **Security awareness training**

## 🔧 Customization

### Adding New Attack Vectors

1. **Modify vulnerable_login.php** to introduce new vulnerabilities
2. **Update modsecurity_rules.conf** with corresponding protection rules
3. **Add test cases** in the HTML forms

### Extending Protection

1. **Add more ModSecurity rules** for different attack types
2. **Implement additional validation** in protected_login.php
3. **Configure fail2ban** for IP-based blocking

## 📚 Additional Resources

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [ModSecurity Reference Manual](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual)
- [OWASP Core Rule Set Documentation](https://coreruleset.org/)
- [AWS EC2 User Guide](https://docs.aws.amazon.com/ec2/index.html)

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
- Review the troubleshooting section in the deployment guide

---

**Remember**: Always practice ethical hacking and responsible disclosure!