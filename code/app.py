from flask import Flask, render_template, request, redirect, url_for, session, flash
import hashlib
import hmac
from cryptography.fernet import Fernet
import sqlite3

app = Flask(__name__, template_folder='templates')
app.secret_key = 'super_secret_key'

# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, key BLOB)''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (sender TEXT, recipient TEXT, message BLOB, key BLOB)''')
    conn.commit()
    conn.close()

init_db()

# Secure message sending using encryption
def encrypt_message(message, key):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message

# User identity verification using authentication
def authenticate_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    hashed_password = hmac.new(key=b'secret_key', msg=password.encode(), digestmod=hashlib.sha256).hexdigest()
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_password))
    user = c.fetchone()
    conn.close()
    if user:
        return True
    else:
        return False

def sign_up(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    hashed_password = hmac.new(key=b'secret_key', msg=password.encode(), digestmod=hashlib.sha256).hexdigest()
    key = Fernet.generate_key()
    c.execute("INSERT INTO users (username, password, key) VALUES (?, ?, ?)", (username, hashed_password, key))
    conn.commit()
    conn.close()

def send_message(sender, recipient, message):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT key FROM users WHERE username=?", (recipient,))
    recipient_key = c.fetchone()
    if recipient_key:
        encrypted_message = encrypt_message(message, recipient_key[0])
        c.execute("INSERT INTO messages (sender, recipient, message, key) VALUES (?, ?, ?, ?)",
                  (sender, recipient, encrypted_message, recipient_key[0]))
        conn.commit()
        print(f"Message sent from {sender} to {recipient} successfully!")
    conn.close()

@app.route('/', methods=['GET', 'POST'])
def index():
    error_message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if authenticate_user(username, password):
            session['username'] = username
            return redirect(url_for('dashboard', username=username))
        else:
            error_message = 'Wrong credentials!'
    return render_template('index.html', error_message=error_message)

@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up_route():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        sign_up(username, password)
        return 'Sign up successful!'
    return render_template('sign_up.html')

@app.route('/dashboard/<username>', methods=['GET', 'POST'])
def dashboard(username):
    if 'username' not in session or session['username'] != username:
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT sender, message, key FROM messages WHERE recipient=?", (username,))
    messages = c.fetchall()
    conn.close()
    
    decrypted_messages = []
    for sender, message, key in messages:
        decrypted_message = decrypt_message(message, key)
        decrypted_messages.append((sender, decrypted_message))
    
    if request.method == 'POST':
        recipient = request.form['recipient']
        message = request.form['message']
        send_message(username, recipient, message)
        return redirect(url_for('dashboard', username=username))
    
    return render_template('dashboard.html', username=username, messages=decrypted_messages)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
