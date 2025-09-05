from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import mysql.connector
import pandas as pd
from datetime import datetime, timedelta
import os
import random
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = "supersecretkey"   

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'YOUR PASSWORD',  
    'database': 'real_estate'
}

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = ""      
app.config['MAIL_PASSWORD'] = ""  
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

mail = Mail(app)

def get_db_connection():
    return mysql.connector.connect(**db_config)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].lower().strip()
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and check_password_hash(user['password'], password):
            if not user.get('is_verified', 0):
                flash("Please verify your account before login.", "warning")
                return redirect(url_for('verify_signup', email=email))
            session['user_id'] = user['id']
            session['email'] = user['email']
            session['name'] = user.get('name') or user['email']
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password", "danger")
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].lower().strip()
        password = request.form['password']
        confirm = request.form['confirm']

        if password != confirm:
            flash("Passwords do not match!", "danger")
            return render_template('signup.html', name=name, email=email)

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            flash("Email already registered. Please login.", "warning")
            return redirect(url_for('login'))

        otp = str(random.randint(100000, 999999))
        expiry = datetime.now() + timedelta(minutes=10)
        hashed = generate_password_hash(password)

        insert_cursor = conn.cursor()
        insert_cursor.execute("""
            INSERT INTO users (name,email,password,is_verified,otp,otp_expiry)
            VALUES (%s,%s,%s,%s,%s,%s)
        """, (name, email, hashed, 0, otp, expiry))
        conn.commit()
        insert_cursor.close()
        cursor.close()
        conn.close()

        try:
            msg = Message("Verify your account", recipients=[email])
            msg.body = f"Your OTP is: {otp} (valid for 10 minutes)"
            mail.send(msg)
            flash("OTP sent to your email. Please verify.", "info")
        except Exception as e:
            flash(f"Failed to send OTP email (server error). You can try 'Resend OTP' after signup. Error: {e}", "warning")

        return redirect(url_for('verify_signup', email=email))
    return render_template('signup.html')

@app.route('/verify-signup/<email>', methods=['GET', 'POST'])
def verify_signup(email):
    email = email.lower().strip()
    if request.method == 'POST':
        otp_input = request.form['otp'].strip()
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if not user:
            flash("No account found for this email.", "danger")
            cursor.close()
            conn.close()
            return redirect(url_for('signup'))

        now = datetime.now()
        if user.get('otp') == otp_input and user.get('otp_expiry') and now <= user['otp_expiry']:
            update_cursor = conn.cursor()
            update_cursor.execute("UPDATE users SET is_verified=1, otp=NULL, otp_expiry=NULL WHERE email=%s", (email,))
            conn.commit()
            update_cursor.close()
            flash("Account verified. You can now login.", "success")
            cursor.close()
            conn.close()
            return redirect(url_for('login'))
        else:
            flash("Invalid or expired OTP", "danger")
        cursor.close()
        conn.close()
    return render_template('verify_signup.html', email=email)

@app.route('/resend-otp/<email>')
def resend_otp(email):
    email = email.lower().strip()
    otp = str(random.randint(100000, 999999))
    expiry = datetime.now() + timedelta(minutes=10)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET otp=%s, otp_expiry=%s WHERE email=%s", (otp, expiry, email))
    conn.commit()
    cursor.close()
    conn.close()

    try:
        msg = Message("Your OTP", recipients=[email])
        msg.body = f"Your OTP is: {otp}\nThis OTP expires in 10 minutes."
        mail.send(msg)
        flash('OTP resent to your email.', 'info')
    except Exception as e:
        flash(f'Failed to send email: {e}', 'danger')

    return redirect(url_for('verify_signup', email=email))

@app.route('/forgot', methods=['GET','POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email'].lower().strip()
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user:
            flash("No account found with that email.", "warning")
            return render_template('forgot.html')

        otp = str(random.randint(100000, 999999))
        expiry = datetime.now() + timedelta(minutes=10)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET otp=%s, otp_expiry=%s WHERE email=%s", (otp, expiry, email))
        conn.commit()
        cursor.close()
        conn.close()

        try:
            msg = Message("Password Reset OTP", recipients=[email])
            msg.body = f"Your OTP to reset password is: {otp} (valid for 10 minutes)"
            mail.send(msg)
            flash("Password reset OTP sent to email.", "info")
        except Exception as e:
            flash(f"Failed to send email: {e}", "danger")

        return redirect(url_for('reset_password', email=email))
    return render_template('forgot.html')

@app.route('/reset/<email>', methods=['GET','POST'])
def reset_password(email):
    email = email.lower().strip()
    if request.method == 'POST':
        otp_input = request.form['otp'].strip()
        password = request.form['password']
        confirm = request.form['confirm']

        if password != confirm:
            flash("Passwords do not match!", "danger")
            return render_template('reset.html', email=email)

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user:
            flash("No account found.", "danger")
            return redirect(url_for('signup'))

        now = datetime.now()
        if user.get('otp') == otp_input and user.get('otp_expiry') and now <= user['otp_expiry']:
            hashed = generate_password_hash(password)
            conn2 = get_db_connection()
            c2 = conn2.cursor()
            c2.execute("UPDATE users SET password=%s, otp=NULL, otp_expiry=NULL WHERE email=%s", (hashed, email))
            conn2.commit()
            c2.close()
            conn2.close()
            flash("Password reset successful. Please login.", "success")
            return redirect(url_for('login'))
        else:
            flash("Invalid or expired OTP", "danger")
    return render_template('reset.html', email=email)

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) AS total FROM Properties")
    row = cursor.fetchone()
    total_properties = row['total'] if row and row.get('total') is not None else 0

    cursor.execute("SELECT COUNT(*) AS total FROM Transactions")
    row = cursor.fetchone()
    total_transactions = row['total'] if row and row.get('total') is not None else 0

    cursor.execute("SELECT AVG(sale_price) AS avg_price FROM Transactions")
    row = cursor.fetchone()
    avg_sale_price = row.get('avg_price') if row else None
    avg_sale_price = round(avg_sale_price, 2) if avg_sale_price else 0

    cursor.close()
    conn.close()

    return render_template('index.html',
        total_properties=total_properties,
        total_transactions=total_transactions,
        avg_sale_price=avg_sale_price
    )

@app.route('/properties')
@login_required
def properties():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT p.*, a.name AS agent_name
        FROM Properties p
        JOIN Agents a ON p.agent_id = a.agent_id
    """)
    props = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('properties.html', properties=props)

@app.route('/reports')
@login_required
def reports():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT city, state, AVG(price) AS avg_price, COUNT(*) AS count
        FROM Properties GROUP BY city, state
    """)
    avg_prices = cursor.fetchall()

    cursor.execute("SELECT * FROM HighDemandAreas")
    high_demand = cursor.fetchall()

    cursor.execute("""
        SELECT p.city, t.sale_date, t.sale_price,
        AVG(t.sale_price) OVER (PARTITION BY p.city ORDER BY t.sale_date ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) AS moving_avg
        FROM Transactions t
        JOIN Properties p ON t.property_id = p.property_id
        ORDER BY p.city, t.sale_date
    """)
    trends = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('reports.html',
        avg_prices=avg_prices,
        high_demand=high_demand,
        trends=trends
    )

@app.route('/export/<report>')
@login_required
def export_csv(report):
    conn = get_db_connection()
    filename = f"exports/{report}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    os.makedirs('exports', exist_ok=True)

    queries = {
        'properties': "SELECT * FROM Properties",
        'transactions': "SELECT * FROM Transactions",
        'avg_prices': """
            SELECT city, state, AVG(price) AS avg_price, COUNT(*) AS count
            FROM Properties GROUP BY city, state
        """,
        'trends': """
            SELECT p.city, t.sale_date, t.sale_price,
            AVG(t.sale_price) OVER (PARTITION BY p.city ORDER BY t.sale_date
                            ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) AS moving_avg
            FROM Transactions t JOIN Properties p ON t.property_id = p.property_id
        """,
        'high_demand': "SELECT * FROM HighDemandAreas"
    }

    if report not in queries:
        conn.close()
        return "Report not found", 400

    df = pd.read_sql(queries[report], conn)
    df.to_csv(filename, index=False)
    conn.close()

    return send_file(filename, as_attachment=True)

@app.route('/export')
@login_required
def export():
    return render_template('export.html')

if __name__ == '__main__':
    app.run(debug=True)
