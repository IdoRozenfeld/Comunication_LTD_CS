import hashlib
import os
import base64
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
import smtplib
from email.mime.text import MIMEText
import random
from dotenv import load_dotenv
from config import password_validation, is_password_reused, update_password_history, record_failed_attempt, is_user_locked

load_dotenv()

# Utility functions for salt and password hashing
def generate_salt():
    return base64.b64encode(os.urandom(16)).decode('utf-8')

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()

app = Flask(__name__, template_folder='../FrontEnd-Secure', static_folder='../FrontEnd-Secure/static')
app.secret_key = os.getenv('SECRET_KEY', 'fallback-key')
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
mysql = MySQL(app)

def create_table():
    with app.app_context():
        try:
            cur = mysql.connection.cursor()
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) NOT NULL,
                    email VARCHAR(100) NOT NULL UNIQUE,
                    password VARCHAR(255) NOT NULL,
                    salt VARCHAR(255) NOT NULL,
                    registration_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
            ''')
            mysql.connection.commit()
            cur.close()
            print("✅ 'users' table is ready!")
        except Exception as e:
            print(f"❌ Error creating table: {str(e)}")

def ensure_registration_date_column():
    with app.app_context():
        try:
            cur = mysql.connection.cursor()
            cur.execute("SHOW COLUMNS FROM users LIKE 'registration_date'")
            result = cur.fetchone()
            if not result:
                cur.execute("""
                    ALTER TABLE users
                    ADD COLUMN registration_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                """)
                mysql.connection.commit()
                print("✅ 'registration_date' column added to 'users' table.")
            else:
                print("ℹ 'registration_date' column already exists.")
            cur.close()
        except Exception as e:
            print(f"❌ Error checking/adding column: {e}")


def create_clients_table():
    with app.app_context():
        try:
            cur = mysql.connection.cursor()
            cur.execute('''
                CREATE TABLE IF NOT EXISTS clients (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    personal_id VARCHAR(20) UNIQUE,
                    first_name VARCHAR(100) NOT NULL,
                    last_name VARCHAR(100) NOT NULL,
                    product_type ENUM('internet', 'phone', 'tv', 'triple') NOT NULL
                );
            ''')
            mysql.connection.commit()
            cur.close()
            print("✅ 'clients' table is ready!")
        except Exception as e:
            print(f"❌ Error creating 'clients' table: {str(e)}")


def insert_dummy_clients():
    dummy_clients = [
        ('123456789', 'Ido', 'Rozenfeld', 'internet'),
        ('111222333', 'Karina', 'Haimov', 'phone'),
        ('456789123', 'Or', 'Drobin', 'tv'),
        ('789123456', 'Liat', 'Simhaev', 'internet'),
        ('456789321', 'Lev', 'Kretz', 'tv'),
        ('987654321', 'Shay', 'Shay', 'triple'),
    ]

    with app.app_context():
        try:
            cur = mysql.connection.cursor()
            cur.executemany('''
                INSERT IGNORE INTO clients (personal_id, first_name, last_name, product_type)
                VALUES (%s, %s, %s, %s)
            ''', dummy_clients)
            mysql.connection.commit()
            cur.close()
            print("✅ Dummy clients inserted.")
        except Exception as e:
            print(f"❌ Error inserting dummy clients: {str(e)}")



@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        from config import is_user_locked, record_failed_attempt

        if is_user_locked(username):
            return render_template('LoginPage.html', error="User is locked for 30 minutes due to failed attempts.")

        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT password, salt FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            cur.close()

            if user:
                stored_hash, stored_salt = user
                entered_hash = hash_password(password, stored_salt)

                if entered_hash == stored_hash:
                    session['username'] = username
                    return redirect(url_for('dashboard'))
                else:
                    record_failed_attempt(username)
                    return render_template('LoginPage.html', error="Invalid credentials")
            else:
                record_failed_attempt(username)
                return render_template('LoginPage.html', error="User not found")

        except Exception as e:
            return render_template('LoginPage.html', error=f"Error: {str(e)}")

    return render_template('LoginPage.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if not password_validation(password):
            return render_template('RegisterPage.html',
                                   error="Password must be at least 10 characters long, include an uppercase letter, a lowercase letter, a number, and a special character.")

        salt = generate_salt()
        hashed_password = hash_password(password, salt)

        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO users (username, email, password, salt) VALUES (%s, %s, %s, %s)",
                        (username, email, hashed_password, salt))
            mysql.connection.commit()
            cur.close()
            return redirect(url_for('login'))
        except Exception as e:
            return render_template('RegisterPage.html', error=f"Error: {str(e)}")

    return render_template('RegisterPage.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        old_pw = request.form['old_password']
        new_pw = request.form['new_password']
        confirm_pw = request.form['confirm_password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT password, salt FROM users WHERE username = %s", (session['username'],))
        user = cur.fetchone()
        cur.close()

        if not user or hash_password(old_pw, user[1]) != user[0]:
            flash("Old password is incorrect.", "error")
            return render_template('change_password.html')

        if hash_password(new_pw, user[1]) == user[0]:
            flash("New password cannot be the same as the old password.", "error")
            return render_template('change_password.html')

        if new_pw != confirm_pw:
            flash("New passwords do not match.", "error")
            return render_template('change_password.html')

        if not password_validation(new_pw):
            flash("Password must be at least 10 characters, include uppercase, lowercase, a digit and a special character.", "error")
            return render_template('change_password.html')

        new_salt = generate_salt()
        new_hash = hash_password(new_pw, new_salt)
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET password = %s, salt = %s WHERE username = %s",
                    (new_hash, new_salt, session['username']))
        mysql.connection.commit()
        cur.close()

        # flash("Password changed successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        code = hashlib.sha1(str(random.randint(100000, 999999)).encode()).hexdigest()
        session['reset_email'] = email
        session['reset_code'] = code

        msg = MIMEText(f"Your reset code is: {code}")
        msg['Subject'] = 'Reset Code'
        msg['From'] = 'idohitproject@gmail.com'
        msg['To'] = email

        try:
            smtp = smtplib.SMTP('smtp.gmail.com', 587)
            smtp.starttls()
            smtp.login('idohitproject@gmail.com', 'xwidavuoferwjfef')
            smtp.send_message(msg)
            smtp.quit()
        except Exception as e:
            return f"Error sending email: {str(e)}"

        return redirect(url_for('verify_reset_code'))

    return render_template('forgot_password.html')

@app.route('/verify_reset_code', methods=['GET', 'POST'])
def verify_reset_code():
    if request.method == 'POST':
        entered = request.form['code']
        if entered == session.get('reset_code'):
            session['code_verified'] = True
            return redirect(url_for('reset_password'))
        else:
            flash("Invalid code", "error")
            return render_template('verify_reset_code.html')
    return render_template('verify_reset_code.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session or not session.get('code_verified'):
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_pw = request.form['new_password']
        confirm_pw = request.form['confirm_password']

        if new_pw != confirm_pw:
            flash("Passwords do not match", "error")
            return render_template('new_password.html')

        if not password_validation(new_pw):
            flash("Password must be at least 10 characters, include uppercase, lowercase, number, and special character.", "error")
            return render_template('new_password.html')

        new_salt = generate_salt()
        new_hash = hash_password(new_pw, new_salt)

        try:
            cur = mysql.connection.cursor()
            cur.execute("UPDATE users SET password = %s, salt = %s WHERE email = %s",
                        (new_hash, new_salt, session['reset_email']))
            mysql.connection.commit()
            cur.close()

            session.pop('reset_email', None)
            session.pop('reset_code', None)
            session.pop('code_verified', None)

            flash("Password updated successfully. Please log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Error: {str(e)}", "error")

    return render_template('new_password.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT email, registration_date FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

        if user:
            email, registration_date = user
            return render_template('dashboard.html', username=username, email=email, member_since=registration_date.strftime('%B %Y'))

    except Exception as e:
        return f"Error loading dashboard: {str(e)}"

    return redirect(url_for('login'))

@app.route('/clients', methods=['GET', 'POST'])
def manage_clients():
    if 'username' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()

    if request.method == 'POST':
        personal_id = request.form['personal_id']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        product_type = request.form['product_type']

        try:
            cur.execute('INSERT INTO clients (personal_id, first_name, last_name, product_type) VALUES (%s, %s, %s, %s)',
                        (personal_id, first_name, last_name, product_type))
            mysql.connection.commit()
        except Exception as e:
            flash(f"error adding: {str(e)}", "error")

    cur.execute('SELECT personal_id, first_name, last_name, product_type, id FROM clients')
    clients = cur.fetchall()
    cur.close()

    return render_template('clients.html', clients=clients)

@app.route('/search_client', methods=['GET'])
def search_client():
    if 'username' not in session:
        return redirect(url_for('login'))

    personal_id = request.args.get('personal_id')

    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT personal_id, first_name, last_name, product_type FROM clients WHERE personal_id = %s", (personal_id,))
        client = cur.fetchone()
        cur.close()

        if client:
            return render_template('client_detail.html', client=client)
        else:
            return f"No client found with Personal ID: {personal_id}"

    except Exception as e:
        return f"Error searching client: {str(e)}"


@app.route('/delete_client/<personal_id>')
def delete_client(personal_id):
    cur = mysql.connection.cursor()
    cur.execute('DELETE FROM clients WHERE personal_id = %s', (personal_id,))
    mysql.connection.commit()
    cur.close()
    return redirect(url_for('manage_clients'))




@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    print("🚀 Connecting to MySQL...")
    create_table()
    ensure_registration_date_column()
    create_clients_table()
    print("🚀 Running Flask on http://127.0.0.1:5000/")
    app.run(debug=True)