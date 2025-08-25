# Quick Start Guide - Python Version

## 🐍 Python Flask Implementation

This guide will help you get started with the Python/Flask version of the cybersecurity demonstration.

### ⚡ Quick Setup (5 minutes)

1. **Install Python dependencies**:
   ```bash
   pip3 install -r requirements.txt
   ```

2. **Set up the database**:
   ```bash
   python3 setup_database.py
   ```
   
3. **Start the application**:
   ```bash
   python3 app.py
   ```

4. **Open your browser** to: `http://localhost:5000`

### 🧪 Testing

Run the test script to verify everything works:
```bash
python3 test_app.py
```

### 🎯 Available Endpoints

- **Home**: `http://localhost:5000/`
- **Vulnerable Form**: `http://localhost:5000/vulnerable`
- **Protected Form**: `http://localhost:5000/protected`

### 🔓 Test Credentials

For testing both forms:

**Vulnerable form** (accepts plain text passwords):
- `demo` / `demo123`
- `guest` / `guest123`

**Protected form** (uses hashed passwords):
- `admin` / `admin123`
- `user` / `user123`
- `test` / `test123`

### 🚨 SQL Injection Payloads

Try these in the **vulnerable form** username field:
```sql
admin' OR '1'='1' --
admin' OR 1=1 #
' UNION SELECT 1,username,password FROM users --
```

### 🛡️ Security Features

The **protected form** will block these attacks using:
- ✅ Prepared statements
- ✅ Input validation
- ✅ Rate limiting
- ✅ CSRF protection
- ✅ Attack detection and logging

### 📋 What's Different from PHP?

| Feature | PHP | Python |
|---------|-----|--------|
| Syntax | `<?php ... ?>` | Clean Python |
| Variables | `$username` | `username` |
| Database | PDO | mysql-connector-python |
| Framework | Raw PHP | Flask |
| Security | Built-in functions | Werkzeug + custom |

### 🎓 Learning Benefits

The Python version is better for beginners because:
- **Cleaner syntax** - easier to read and understand
- **Better error messages** - more helpful for debugging
- **Industry standard** - Python is widely used in cybersecurity
- **Great documentation** - extensive learning resources available

### 📝 Code Structure

```python
# Vulnerable (educational only)
sql_query = f"SELECT * FROM users WHERE username = '{username}'"

# Secure (production-ready)
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
```

### 🐛 Troubleshooting

**Database connection issues?**
- Make sure MySQL is running
- Check credentials in `setup_database.py`
- Verify the database was created successfully

**Module import errors?**
- Run: `pip3 install -r requirements.txt`
- Check Python version: `python3 --version` (3.7+ required)

**Port already in use?**
- Change the port in `app.py`: `app.run(port=5001)`
- Or stop the conflicting service

### 🎉 You're Ready!

Start exploring SQL injection vulnerabilities and learn how to prevent them with proper coding practices!