from flask import Flask, request, redirect, url_for, session
import sqlite3
import json
import re
import hmac
import hashlib
import html
import os

app = Flask(__name__)
app.secret_key = "super_secure_communication_ltd_2026"


# --- טעינת קונפיגורציה ---
def load_config():
    with open('config.json', 'r') as f:
        return json.load(f)


# --- פונקציות אבטחה (HMAC, Salt, Complexity) ---
def validate_password(password):
    config = load_config()
    if len(password) < config['min_length']:
        return False, f"הסיסמה חייבת להכיל לפחות {config['min_length']} תווים."
    if config['require_complexity']['uppercase'] and not re.search(r"[A-Z]", password):
        return False, "הסיסמה חייבת להכיל לפחות אות גדולה אחת באנגלית."
    if config['require_complexity']['digits'] and not re.search(r"\d", password):
        return False, "הסיסמה חייבת להכיל לפחות ספרה אחת."
    if any(word in password.lower() for word in config['forbidden_words']):
        return False, "הסיסמה מכילה מילה נפוצה או אסורה."
    return True, ""


def hash_password_hmac(password, salt=None):
    config = load_config()
    if not salt:
        salt = os.urandom(16).hex()
    key = config['hmac_secret_key'].encode()
    message = (password + salt).encode()
    pw_hash = hmac.new(key, message, hashlib.sha256).hexdigest()
    return pw_hash, salt


# --- עטיפת HTML מודרנית מימין לשמאל (RTL) ---
def wrap_html(content):
    return f'''
    <!DOCTYPE html>
    <html lang="he" dir="rtl">
    <head>
        <meta charset="UTF-8">
        <title>Communication_LTD | אזור מאובטח</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
            .container {{ background: rgba(255, 255, 255, 0.05); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.1); padding: 40px; border-radius: 16px; text-align: right; width: 100%; max-width: 400px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); box-sizing: border-box; }}
            input {{ width: 100%; padding: 12px; margin: 10px 0; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.2); background: rgba(0, 0, 0, 0.2); color: #fff; box-sizing: border-box; text-align: right; transition: 0.3s; }}
            input:focus {{ outline: none; border-color: #6366f1; }}
            button {{ width: 100%; padding: 12px; background: #6366f1; color: white; border: none; border-radius: 8px; font-weight: bold; cursor: pointer; margin-top: 10px; transition: 0.3s; }}
            button:hover {{ background: #4f46e5; }}
            a {{ color: #818cf8; text-decoration: none; font-size: 0.9rem; }}
            a:hover {{ text-decoration: underline; }}
            h2 {{ text-align: center; margin-bottom: 20px; color: #fff; }}
            .alert {{ background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; padding: 10px; border-radius: 6px; margin-bottom: 15px; font-size: 0.9rem; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="container">
            {content}
        </div>
    </body>
    </html>
    '''


# --- הגדרת מסד הנתונים ---
def get_db_connection():
    conn = sqlite3.connect('secure_communication.db')
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users 
                    (id INTEGER PRIMARY KEY, username TEXT UNIQUE, email TEXT, 
                     password_hash TEXT, salt TEXT, failed_attempts INTEGER DEFAULT 0)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS customers 
                    (id INTEGER PRIMARY KEY, name TEXT)''')
    conn.commit()
    conn.close()


# --- ניתובים (Routes) ---

@app.route('/')
def index():
    return redirect(url_for('login'))


# 1. הרשמה (עם שמירת נתונים ל-UX חלקה והגנת Reflected XSS)
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = ""
    # משתנים לשמירת הקלט של המשתמש במקרה של שגיאה
    saved_username = ""
    saved_email = ""

    if request.method == 'POST':
        # שמירת הנתונים וקידודם כדי למנוע Reflected XSS
        saved_username = html.escape(request.form['username'])
        saved_email = html.escape(request.form['email'])

        password = request.form['password']

        # אימות סיסמה מול קובץ config
        valid, msg = validate_password(password)
        if not valid:
            error = f'<div class="alert">{msg}</div>'
        else:
            pw_hash, salt = hash_password_hmac(password)
            try:
                conn = get_db_connection()
                # תקין ומוגן נגד SQL Injection
                conn.execute('INSERT INTO users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)',
                             (request.form['username'], request.form['email'], pw_hash, salt))
                conn.commit()
                conn.close()
                return wrap_html(
                    '<h2>נרשמת בהצלחה!</h2><p style="text-align:center;"><a href="/login">מעבר להתחברות</a></p>')
            except sqlite3.IntegrityError:
                error = '<div class="alert">שם המשתמש כבר קיים במערכת.</div>'

    # השדות מתמלאים אוטומטית בערכים שנשמרו (אם ישנם)
    content = f'''
        <h2>יצירת חשבון מאובטח</h2>
        {error}
        <form method="post">
            <input name="username" value="{saved_username}" placeholder="שם משתמש" required>
            <input name="email" type="email" value="{saved_email}" placeholder="אימייל" required>
            <input name="password" type="password" placeholder="סיסמה (לפחות 10 תווים, אות גדולה וספרה)" required>
            <button type="submit">הרשמה</button>
        </form>
        <p style="text-align:center; margin-top:15px;">כבר יש לך חשבון? <a href="/login">התחבר כאן</a></p>
    '''
    return wrap_html(content)

# 2. התחברות (מוגן SQLi ומנגנון נעילה לאחר 3 ניסיונות)
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        config = load_config()

        conn = get_db_connection()
        # מוגן SQL Injection! (שימוש ב-?)
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user:
            if user['failed_attempts'] >= config['max_login_attempts']:
                error = '<div class="alert">החשבון ננעל עקב יותר מדי ניסיונות כושלים. פנה למנהל המערכת.</div>'
            else:
                check_hash, _ = hash_password_hmac(password, user['salt'])
                if check_hash == user['password_hash']:
                    # איפוס ספירת ניסיונות כושלים בהתחברות מוצלחת
                    conn.execute('UPDATE users SET failed_attempts = 0 WHERE id = ?', (user['id'],))
                    conn.commit()
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    conn.close()
                    return redirect(url_for('system_screen'))
                else:
                    # העלאת ספירת הניסיונות הכושלים
                    conn.execute('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?', (user['id'],))
                    conn.commit()
                    error = '<div class="alert">שם משתמש או סיסמה שגויים.</div>'
        else:
            error = '<div class="alert">שם משתמש או סיסמה שגויים.</div>'
        conn.close()

    content = f'''
        <h2>התחברות למערכת</h2>
        {error}
        <form method="post">
            <input name="username" placeholder="שם משתמש" required>
            <input name="password" type="password" placeholder="סיסמה" required>
            <button type="submit">התחבר</button>
        </form>
        <p style="text-align:center; margin-top:15px;">אין לך חשבון? <a href="/register">צור חשבון חדש</a></p>
    '''
    return wrap_html(content)


# 3. מסך המערכת (מוגן Stored XSS)
@app.route('/system', methods=['GET', 'POST'])
def system_screen():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    last_added = ""
    conn = get_db_connection()

    if request.method == 'POST':
        raw_cust_name = request.form['customer_name']

        # מוגן Stored XSS! קידוד תווים מיוחדים לפני הכנסה והצגה
        safe_cust_name = html.escape(raw_cust_name)

        # מוגן SQLi
        conn.execute('INSERT INTO customers (name) VALUES (?)', (safe_cust_name,))
        conn.commit()
        last_added = f'<h3 style="color:#10b981; text-align:center;">לקוח אחרון שהתווסף: {safe_cust_name}</h3>'

    content = f'''
        <h2>לוח בקרה - Communication_LTD</h2>
        <p style="text-align:center;">מחובר כ: <b>{session['username']}</b></p>
        <form method="post">
            <input name="customer_name" placeholder="שם הלקוח המלא" required>
            <button type="submit">הוסף לקוח</button>
        </form>
        {last_added}
        <div style="text-align:center; margin-top: 30px;">
            <a href="/logout">התנתק מהמערכת</a>
        </div>
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