from flask import Flask, request, redirect, url_for, session
import sqlite3
import hashlib
import secrets

app = Flask(__name__)
app.secret_key = "vulnerable_secret_key_123"


# --- Simple HTML Wrapper for Vulnerable Version ---
def wrap_html(content):
    return f'''
    <!DOCTYPE html>
    <html lang="he" dir="rtl">
    <head>
        <meta charset="UTF-8">
        <title>Communication_LTD | Vulnerable Portal</title>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1e1e24; color: #fff; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
            .container {{ background: #2a2a35; padding: 40px; border-radius: 12px; text-align: right; width: 100%; max-width: 400px; box-sizing: border-box; }}
            input {{ width: 100%; padding: 10px; margin: 10px 0; border-radius: 6px; border: 1px solid #444; background: #111; color: #fff; box-sizing: border-box; text-align: right; }}
            button {{ width: 100%; padding: 10px; background: #e53e3e; color: white; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; margin-top: 10px; }}
            a {{ color: #63b3ed; text-decoration: none; }}
            h2 {{ text-align: center; margin-bottom: 20px; }}
            p {{ text-align: center; }}
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
def get_db_connection():
    conn = sqlite3.connect('vulnerable_communication.db')
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users 
                    (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT, reset_token TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS customers 
                    (id INTEGER PRIMARY KEY, name TEXT)''')
    conn.commit()
    conn.close()


# --- Routes ---

@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        query = f"INSERT INTO users (username, email, password) VALUES ('{username}', '{email}', '{password}')"
        conn.execute(query)
        conn.commit()
        conn.close()
        return wrap_html('<h2>משתמש נרשם בהצלחה!</h2><a href="/login">מעבר להתחברות</a>')

    content = '''
        <h2>הרשמה (גרסה פגיעה)</h2>
        <form method="post">
            <input name="username" placeholder="שם משתמש" required>
            <input name="email" type="email" placeholder="אימייל" required>
            <input name="password" type="password" placeholder="סיסמה" required>
            <button type="submit">הרשמה</button>
        </form>
        <p><a href="/login">כבר יש לך חשבון? התחבר כאן</a></p>
    '''
    return wrap_html(content)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        user = conn.execute(query).fetchone()
        conn.close()

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('system_screen'))
        else:
            error = '<p style="color:red">שם משתמש או סיסמה שגויים</p>'

    content = f'''
        <h2>התחברות (גרסה פגיעה)</h2>
        {error}
        <form method="post">
            <input name="username" placeholder="שם משתמש" required>
            <input name="password" type="password" placeholder="סיסמה" required>
            <button type="submit">התחבר</button>
        </form>
        <p><a href="/forgot-password">שכחת סיסמה?</a></p>
        <p><a href="/register">אין לך חשבון? הירשם כאן</a></p>
    '''
    return wrap_html(content)


@app.route('/system', methods=['GET', 'POST'])
def system_screen():
    if 'user_id' not in session: return redirect(url_for('login'))

    # פיצ'ר חסימה: אם הלקוח כבר הוסיף שם בסשן זה, הוא מועבר ישר למסך הסיכום
    if session.get('customer_added'):
        return redirect(url_for('success_screen'))

    conn = get_db_connection()
    if request.method == 'POST':
        cust_name = request.form['customer_name']
        # VULNERABLE: SQL Injection
        conn.execute(f"INSERT INTO customers (name) VALUES ('{cust_name}')")
        conn.commit()
        conn.close()

        # סימון בסשן שההוספה בוצעה ומעבר למסך הבחירה החדש
        session['customer_added'] = True
        return redirect(url_for('success_screen'))

    content = f'''
        <h2>מערכת (גרסה פגיעה)</h2>
        <p>מחובר כ: {session['username']}</p>
        <form method="post">
            <input name="customer_name" placeholder="שם לקוח חדש" required>
            <button type="submit">הוסף לקוח</button>
        </form>
        <br>
        <a href="/change-password">שינוי סיסמה</a> | <a href="/logout">התנתק</a>
    '''
    conn.close()
    return wrap_html(content)


# --- מסך הבחירה החדש לאחר הוספה (גרסה פגיעה - מציג Stored XSS) ---
@app.route('/success')
def success_screen():
    if 'user_id' not in session: return redirect(url_for('login'))

    conn = get_db_connection()
    # שליפת השורה האחרונה מהמסד כדי להציג את ה-Stored XSS בצורה פגיעה לחלוטין
    customer = conn.execute("SELECT * FROM customers ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()

    cust_name = customer['name'] if customer else "אין לקוחות"

    content = f'''
        <h2>הלקוח התווסף בהצלחה!</h2>
        <h3 style="color:#ef4444; text-align:center;">לקוח אחרון בבסיס הנתונים: {cust_name}</h3>
        <br>
        <div style="text-align:center;">
            <a href="/change-password">שינוי סיסמה משתמש</a> | <a href="/logout">התנתק מהמערכת</a>
        </div>
    '''
    return wrap_html(content)


@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session: return redirect(url_for('login'))
    error = ""

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']

        conn = get_db_connection()
        query = f"SELECT * FROM users WHERE id = {session['user_id']} AND password = '{old_password}'"
        user = conn.execute(query).fetchone()

        if user:
            update_query = f"UPDATE users SET password = '{new_password}' WHERE id = {session['user_id']}"
            conn.execute(update_query)
            conn.commit()
            conn.close()
            return wrap_html('<h2>הסיסמה שונתה בהצלחה!</h2><a href="/system">חזרה למערכת</a>')
        else:
            error = '<p style="color:red">הסיסמה הנוכחית שגויה</p>'
        conn.close()

    content = f'''
        <h2>שינוי סיסמה</h2>
        {error}
        <form method="post">
            <input name="old_password" type="password" placeholder="סיסמה נוכחית" required>
            <input name="new_password" type="password" placeholder="סיסמה חדשה" required>
            <button type="submit">שנה סיסמה</button>
        </form>
        <a href="/system">ביטול</a>
    '''
    return wrap_html(content)


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        random_val = secrets.token_hex(8)
        sha1_token = hashlib.sha1(random_val.encode()).hexdigest()

        conn = get_db_connection()
        query = f"UPDATE users SET reset_token = '{sha1_token}' WHERE email = '{email}'"
        conn.execute(query)
        conn.commit()
        conn.close()

        content = f'''
            <h2>שחזור סיסמה</h2>
            <p>טוקן השחזור שלך (SHA-1):</p>
            <code>{sha1_token}</code>
            <form action="/verify-token" method="post" style="margin-top:20px;">
                <input type="hidden" name="email" value="{email}">
                <input name="token" placeholder="הזן את הטוקן שקיבלת" required>
                <button type="submit">אמת טוקן ושנה סיסמה</button>
            </form>
        '''
        return wrap_html(content)

    return wrap_html('''
        <h2>שכחתי סיסמה</h2>
        <form method="post">
            <input name="email" type="email" placeholder="הזן את כתובת האימייל שלך" required>
            <button type="submit">שלח טוקן שחזור</button>
        </form>
        <a href="/login">חזרה להתחברות</a>
    ''')


@app.route('/verify-token', methods=['POST'])
def verify_token():
    email = request.form['email']
    token = request.form['token']

    conn = get_db_connection()
    query = f"SELECT * FROM users WHERE email = '{email}' AND reset_token = '{token}'"
    user = conn.execute(query).fetchone()
    conn.close()

    if user:
        session['user_id'] = user['id']
        session['username'] = user['username']
        return redirect(url_for('change_password'))
    else:
        return wrap_html('<p style="color:red">טוקן שגוי.</p><a href="/forgot-password">נסה שוב</a>')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    init_db()
    app.run(port=5000, debug=True)