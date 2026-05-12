from flask import Flask, request, redirect, url_for, session, render_template_string
import sqlite3
import secrets
from security_utils import validate_password_complexity, hash_password_hmac, generate_sha1_token

app = Flask(__name__)
# Secret key for encrypting browser sessions
app.secret_key = "communication_ltd_2026_secure_key" 

# --- UI Wrapper for Modern Design ---
def wrap_html(content):
    """Wraps every page in a modern Glassmorphism container."""
    return f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Communication_LTD | Secure Portal</title>
        <link rel="stylesheet" href="/static/style.css">
    </head>
    <body>
        <div class="container">
            {content}
        </div>
    </body>
    </html>
    '''

# --- Database Management (Requirement 1) ---
def get_db_connection():
    conn = sqlite3.connect('communication_ltd.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the relational database for users and customers."""
    conn = get_db_connection()
    # Requirement 1: Relational DB (Users table)
    conn.execute('''CREATE TABLE IF NOT EXISTS users 
                    (id INTEGER PRIMARY KEY, username TEXT UNIQUE, email TEXT, 
                     password_hash TEXT, salt TEXT, reset_token TEXT)''')
    # Requirement 4: Customers table
    conn.execute('''CREATE TABLE IF NOT EXISTS customers 
                    (id INTEGER PRIMARY KEY, name TEXT)''')
    conn.commit()
    conn.close()

# --- Routes ---

@app.route('/')
def index():
    return redirect(url_for('login'))

# 1. Register Screen (Requirement 1)
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = ""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # 1b: Complexity check (12 chars minimum in config.json)
        valid, msg = validate_password_complexity(password)
        if not valid: 
            error = f'<div class="alert">{msg}</div>'
        else:
            # 1c: Security - HMAC + Salt
            pw_hash, salt = hash_password_hmac(password)
            try:
                conn = get_db_connection()
                conn.execute('INSERT INTO users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)',
                             (username, email, pw_hash, salt))
                conn.commit()
                conn.close()
                return wrap_html('<h2>Success!</h2><p>Account created.</p><a href="/login">Go to Login</a>')
            except sqlite3.IntegrityError:
                error = '<div class="alert">Username already exists.</div>'
            
    content = f'''
        <h2>Join the Future</h2>
        <p style="opacity:0.7">Communication_LTD Portal</p>
        {error}
        <form method="post">
            <input name="username" placeholder="Choose Username" required>
            <input name="email" type="email" placeholder="Email Address" required>
            <input name="password" type="password" placeholder="Password (min 12 chars)" required>
            <button type="submit">Create Account</button>
        </form>
        <hr style="opacity:0.1; margin: 20px 0;">
        <p>Existing user? <a href="/login">Sign In</a></p>
    '''
    return wrap_html(content)

# 3. Login Screen (Requirement 3)
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        # 3c: Check existence and return message
        if user:
            check_hash, _ = hash_password_hmac(password, user['salt'])
            if check_hash == user['password_hash']:
                session['user_id'] = user['id']
                session['username'] = user['username']
                return redirect(url_for('system_screen'))
        
        error = '<div class="alert">Invalid username or password.</div>'

    content = f'''
        <h2>Welcome Back</h2>
        {error}
        <form method="post">
            <input name="username" placeholder="Username" required>
            <input name="password" type="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
        <p><a href="/forgot-password">Forgot password?</a></p>
        <hr style="opacity:0.1; margin: 20px 0;">
        <p>New here? <a href="/register">Create an account</a></p>
    '''
    return wrap_html(content)

# 4. System Screen (Requirement 4)
@app.route('/system', methods=['GET', 'POST'])
def system_screen():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    last_added = ""
    if request.method == 'POST':
        cust_name = request.form['customer_name']
        conn = get_db_connection()
        conn.execute('INSERT INTO customers (name) VALUES (?)', (cust_name,))
        conn.commit()
        conn.close()
        # 4b: Display name of the last entered customer
        last_added = f'<h3 style="color:#10b981">Added: {cust_name}</h3>'

    content = f'''
        <h2>System Dashboard</h2>
        <p>Operator: <b>{session['username']}</b></p>
        <form method="post">
            <input name="customer_name" placeholder="New Customer Full Name" required>
            <button type="submit">Register Customer</button>
        </form>
        {last_added}
        <div style="margin-top: 30px; font-size: 0.9rem;">
            <a href="/change-password">Update Password</a> | <a href="/logout">Logout</a>
        </div>
    '''
    return wrap_html(content)

# 2. Change Password Screen (Requirement 2)
@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session: return redirect(url_for('login'))
    error = ""
    if request.method == 'POST':
        old_pw = request.form['old_password']
        new_pw = request.form['new_password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        
        # 2a: Verify existing password
        check_hash, _ = hash_password_hmac(old_pw, user['salt'])
        if check_hash != user['password_hash']:
            conn.close()
            error = '<div class="alert">Current password is incorrect.</div>'
        else:
            # 2b: New password must meet config requirements
            valid, msg = validate_password_complexity(new_pw)
            if not valid:
                conn.close()
                error = f'<div class="alert">{msg}</div>'
            else:
                new_hash, new_salt = hash_password_hmac(new_pw)
                conn.execute('UPDATE users SET password_hash = ?, salt = ? WHERE id = ?', 
                             (new_hash, new_salt, session['user_id']))
                conn.commit()
                conn.close()
                return wrap_html('<h2>Updated!</h2><p>Password changed.</p><a href="/system">Back to Dashboard</a>')

    content = f'''
        <h2>Update Security</h2>
        {error}
        <form method="post">
            <input name="old_password" type="password" placeholder="Current Password" required>
            <input name="new_password" type="password" placeholder="New Secure Password" required>
            <button type="submit">Update Password</button>
        </form>
        <br><a href="/system">Cancel</a>
    '''
    return wrap_html(content)

# 5. Forgot Password Screen (Requirement 5)
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        # 5b: Generate random value
        raw_token = secrets.token_hex(8)
        # 5c: Define using SHA-1
        sha1_token = generate_sha1_token(raw_token)
        
        conn = get_db_connection()
        conn.execute('UPDATE users SET reset_token = ? WHERE email = ?', (sha1_token, email))
        conn.commit()
        conn.close()
        
        # Simulation of sending email
        content = f'''
            <h2>Verify Identity</h2>
            <p>A SHA-1 token was generated for: <b>{email}</b></p>
            <div style="background:rgba(255,255,255,0.1); padding:10px; border-radius:8px; margin:15px 0;">
                <code>{sha1_token}</code>
            </div>
            <form action="/verify-token" method="post">
                <input name="token" placeholder="Enter SHA-1 Token" required>
                <input type="hidden" name="email" value="{email}">
                <button type="submit">Verify & Reset</button>
            </form>
        '''
        return wrap_html(content)

    return wrap_html('''
        <h2>Account Recovery</h2>
        <form method="post">
            <input name="email" type="email" placeholder="Enter your Email" required>
            <button type="submit">Send Token</button>
        </form>
        <br><a href="/login">Back to Login</a>
    ''')

@app.route('/verify-token', methods=['POST'])
def verify_token():
    token = request.form['token']
    email = request.form['email']
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ? AND reset_token = ?', (email, token)).fetchone()
    conn.close()
    
    if user:
        # 5d: User is redirected to password change window
        session['user_id'] = user['id']
        session['username'] = user['username']
        return redirect(url_for('change_password'))
    return wrap_html('<h2>Error</h2><p>Invalid Token.</p><a href="/forgot-password">Try again</a>')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)