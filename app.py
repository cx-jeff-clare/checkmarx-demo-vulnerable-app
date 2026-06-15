"""
Vulnerable Flask App for Checkmarx T&R Demo
Optimized for T&R limitations: ~10 findings total
Mix: 3-4 exploitable/reachable, 6-7 not exploitable/unreachable
Author: Jeff Clare
Date: June 2026
Current Attempt: 1
"""

import os
import sqlite3
import hashlib
from flask import Flask, request, render_template_string, jsonify

app = Flask(__name__)
app.secret_key = "hardcoded-secret-key-abc123"  # VULN: Hardcoded secret (in unreachable config context)

# ============================================================================
# DATABASE SETUP
# ============================================================================
def init_db():
    conn = sqlite3.connect("demo.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ============================================================================
# EXPLOITABLE/REACHABLE VULNS (3 findings)
# ============================================================================

@app.route('/user/<user_id>')
def get_user(user_id):
    """
    VULN: SQL Injection - EXPLOITABLE & REACHABLE
    User-supplied user_id directly concatenated into SQL query
    """
    conn = sqlite3.connect("demo.db")
    cursor = conn.cursor()
    # Fixed: Using parameterized query to prevent SQL injection
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    result = cursor.fetchone()
    conn.close()
    return jsonify({"user": result})


@app.route('/search')
def search():
    """
    VULN: Reflected XSS - EXPLOITABLE & REACHABLE
    Search parameter rendered directly to HTML without escaping
    /search?q=<script>alert('xss')</script>
    """
    query = request.args.get('q', '')
    html = f"""
    <html>
    <body>
        <h1>Search Results for: {query}</h1>
    </body>
    </html>
    """
    return html


@app.route('/login', methods=['POST'])
def login():
    """
    VULN: Weak Password Hashing - EXPLOITABLE & REACHABLE
    Using MD5 (cryptographically broken) to hash passwords
    """
    username = request.form.get('username')
    password = request.form.get('password')
    
    # VULN: MD5 is broken
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    return jsonify({"authenticated": True, "hash": password_hash})


# ============================================================================
# NOT EXPLOITABLE/NOT REACHABLE VULNS (7 findings - noise)
# ============================================================================

# VULN 1: Hardcoded secret in dead code (never called)
def old_api_endpoint():
    """
    VULN: Hardcoded API key - NOT REACHABLE (function never called)
    This function is never invoked, so endpoint doesn't exist
    """
    api_key = "sk-demo-old-api-key-12345"
    return api_key


# VULN 2: SQL Injection in unreachable function
def admin_lookup_unused(admin_id):
    """
    VULN: SQL Injection - NOT REACHABLE (function never called)
    Similar to get_user but this function is never used
    """
    conn = sqlite3.connect("demo.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM admins WHERE id = '{admin_id}'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result


# VULN 3: Hardcoded credentials in unused class
class LegacyAuth:
    """
    VULN: Hardcoded credentials - NOT REACHABLE (class never instantiated)
    This class is defined but never used anywhere in the app
    """
    def __init__(self):
        self.username = "legacy_admin"
        self.password = "old_password_123"
    
    def authenticate(self, user, pwd):
        return user == self.username and pwd == self.password


# VULN 4: XSS in commented-out route
# @app.route('/old_search')
# def old_search():
#     """VULN: Reflected XSS in commented code - NOT REACHABLE"""
#     query = request.args.get('q', '')
#     return f"<h1>{query}</h1>"


# VULN 5: Command injection in dead code
def ping_host_unused(hostname):
    """
    VULN: OS Command Injection - NOT REACHABLE (function never called)
    While the function has the vuln, it's never invoked
    """
    import subprocess
    result = subprocess.run(f"ping -c 1 {hostname}", shell=True, capture_output=True)
    return result.stdout.decode()


# VULN 6: Hardcoded password in test code
TEST_MODE_PASSWORD = "test_password_hardcoded"  # VULN: Hardcoded - NOT EXPLOITABLE in production


# VULN 7: Insecure deserialization in unused function
def load_config_unused(data):
    """
    VULN: Insecure Deserialization (pickle) - NOT REACHABLE (never called)
    This function uses unsafe pickle.loads but is never invoked
    """
    import pickle
    config = pickle.loads(data)
    return config


# ============================================================================
# UTILITY ROUTES
# ============================================================================

@app.route('/')
def index():
    return jsonify({
        "app": "Checkmarx T&R Demo App",
        "exploitable_endpoints": [
            "/user/<user_id> - SQL Injection",
            "/search?q=<value> - Reflected XSS",
            "/login (POST) - Weak crypto (MD5)"
        ],
        "status": "Ready for Checkmarx scan"
    })


@app.route('/health')
def health():
    return jsonify({"status": "ok"})


# ============================================================================
# MAIN
# ============================================================================
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
