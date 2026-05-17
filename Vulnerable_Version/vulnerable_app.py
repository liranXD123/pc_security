from flask import Flask, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = "vulnerable_secret_key_123"


# --- Simple HTML Wrapper for Vulnerable Version ---
def wrap_html(content):
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Communication_LTD | Vulnerable Portal</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #1e1e24; color: #fff; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
            .container {{ background: #2a2a35; padding: 40px; border-radius: 12px; text-align: center; width: 100%; max-width: 400px; }}
            input {{ width: 100%; padding: 10px; margin: 10px 0; border-radius: 6px; border: 1px solid #444; background: #111; color: #fff; box-sizing: border-box; }}
            button {{ width: 100%; padding: 10px; background: #e53e3e; color: white; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; }}
            a {{ color: #63b3ed; text-decoration: none; }}
        </style>
    </head>
    <body>
        <div class="container">
            {content}
        </div>
    </body>
    </html>
    '''


# --- Database Setup (Vulnerable to SQLi) ---
import sqlite3


def get_db_connection():
    conn = sqlite3.connect('vulnerable_communication.db')
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    # In the vulnerable version, passwords are kept in PLAIN TEXT to easily demonstrate login bypass!
    conn.execute('''CREATE TABLE IF NOT EXISTS users 
                    (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS customers 
                    (id INTEGER PRIMARY KEY, name TEXT)''')
    conn.commit()
    conn.close()


# --- Routes ---

@app.route('/')
def index():
    return redirect(url_for('login'))


# 1. Register Screen (Vulnerable - No complexity checks, vulnerable insert)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        # VULNERABLE: Direct string concatenation allows SQL Injection during registration
        query = f"INSERT INTO users (username, email, password) VALUES ('{username}', '{email}', '{password}')"
        conn.execute(query)
        conn.commit()
        conn.close()
        return wrap_html('<h2>User Registered!</h2><a href="/login">Go to Login</a>')

    content = '''
        <h2>Vulnerable Register</h2>
        <form method="post">
            <input name="username" placeholder="Username" required>
            <input name="email" type="email" placeholder="Email" required>
            <input name="password" type="password" placeholder="Password" required>
            <button type="submit">Register</button>
        </form>
        <p><a href="/login">Already have an account? Login</a></p>
    '''
    return wrap_html(content)


# 3. Login Screen (VULNERABLE TO SQL INJECTION)
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        # VULNERABLE: String formatting allows bypassing the login via: ' OR '1'='1
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        user = conn.execute(query).fetchone()
        conn.close()

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('system_screen'))
        else:
            error = '<p style="color:red">Invalid Credentials</p>'

    content = f'''
        <h2>Vulnerable Login</h2>
        {error}
        <form method="post">
            <input name="username" placeholder="Username" required>
            <input name="password" type="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <p>Don't have an account? <a href="/register">Register here</a></p>
    '''
    return wrap_html(content)


# 4. System Screen (VULNERABLE TO STORED XSS & SQLi)
@app.route('/system', methods=['GET', 'POST'])
def system_screen():
    if 'user_id' not in session: return redirect(url_for('login'))

    last_added = ""
    conn = get_db_connection()

    if request.method == 'POST':
        cust_name = request.form['customer_name']
        # VULNERABLE: SQL Injection on inserting customer
        conn.execute(f"INSERT INTO customers (name) VALUES ('{cust_name}')")
        conn.commit()
        # VULNERABLE: Direct rendering of raw input causes Stored XSS
        last_added = f'<h3 style="color:red">Last Added: {cust_name}</h3>'

    content = f'''
        <h2>System Dashboard (Vulnerable)</h2>
        <p>Operator: {session['username']}</p>
        <form method="post">
            <input name="customer_name" placeholder="Customer Name" required>
            <button type="submit">Add Customer</button>
        </form>
        {last_added}
        <br><a href="/logout">Logout</a>
    '''
    conn.close()
    return wrap_html(content)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    init_db()
    app.run(port=5000, debug=True)