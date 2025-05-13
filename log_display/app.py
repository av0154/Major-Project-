import os
import re
import json
import joblib
import numpy as np
from flask import Flask, jsonify, render_template, request, redirect, session
from datetime import datetime
import requests
from crypto_utils import encrypt_message
import hashlib

app = Flask(__name__)
app.secret_key = os.urandom(24)  

LOG_DIR = r'D:\Major Project\login'
SECRET_MESSAGE = "AUTH_KASHYAPA"
DDOS_MODEL_PATH = r"D:\Major Project\ddos_model.pkl"
DDOS_LOG_FILE = r'D:\Major Project\login\request_app.log'
REQUEST_LOG_FILE = os.path.join(LOG_DIR, 'request_app.log')

USERS_JSON_PATH = r'D:\Major Project\log_display\users.json'

ddos_model = joblib.load(DDOS_MODEL_PATH)

def load_users():
    try:
        with open(USERS_JSON_PATH, 'r') as f:
            data = json.load(f)
        return data['users']
    except FileNotFoundError:
        return []

def check_user_credentials(username, password):
    users = load_users()
    for user in users:
        if user['username'] == username:
            if user['password'] == password:  
                return True
    return False

def parse_login_attempts(file_path):
    logs = []
    pattern = r'\[(.*?)\] IP: (.*?), Username: (.*?), SQLi Suspected: (True|False)'
    try:
        with open(file_path, 'r') as file:
            for line in file:
                match = re.match(pattern, line)
                if match:
                    timestamp, ip, username, sqli = match.groups()
                    logs.append({'timestamp': timestamp, 'ip': ip, 'username': username, 'sqli': sqli})
    except FileNotFoundError:
        logs.append({'timestamp': '', 'ip': '', 'username': '', 'sqli': 'Log file not found'})
    return logs

def parse_unauthorized_access(file_path):
    logs = []
    pattern = r'\[(.*?)\] Failed login attempt\. IP: (.*?), Username: (.*)'
    try:
        with open(file_path, 'r') as file:
            for line in file:
                match = re.match(pattern, line)
                if match:
                    timestamp, ip, username = match.groups()
                    logs.append({'timestamp': timestamp, 'ip': ip, 'username': username})
    except FileNotFoundError:
        logs.append({'timestamp': '', 'ip': '', 'username': 'Log file not found'})
    return logs

def parse_request_logs(file_path):
    logs = []
    pattern = r'\[(.*?)\] Sender IP: (.*?), Receiver IP: (.*?), URL: (.*?), Method: (.*?), UA: (.*?), Status: (\d+)'
    try:
        with open(file_path, 'r') as file:
            for line in file:
                match = re.match(pattern, line)
                if match:
                    timestamp, sender_ip, receiver_ip, url, method, ua, status = match.groups()
                    logs.append({
                        'timestamp': timestamp,
                        'sender_ip': sender_ip,
                        'receiver_ip': receiver_ip,
                        'url': url,
                        'method': method,
                        'ua': ua,
                        'status': status
                    })
    except FileNotFoundError:
        logs.append({'timestamp': '', 'sender_ip': '', 'receiver_ip': '', 'url': '', 'method': '', 'ua': '', 'status': 'Log file not found'})
    return logs

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'username' in session:
        return redirect('/dashboard')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if check_user_credentials(username, password):
            session['username'] = username
            return redirect('/dashboard')
        else:
            return render_template('login.html', error="Invalid username or password")

    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if check_user_credentials(username, password):
            session['username'] = username
            return redirect('/dashboard')
        else:
            return render_template('login.html', error="Invalid username or password")

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')

    login_attempts = requests.get('http://127.0.0.1:5001/api/login-attempts').json()
    unauthorized_access = requests.get('http://127.0.0.1:5001/api/unauthorized-access').json()
    authentication_transactions = requests.get('http://127.0.0.1:5001/api/authentication-transactions').json()
    ddos_logs = requests.get('http://127.0.0.1:5001/api/ddos-logs').json()
    request_logs = requests.get('http://127.0.0.1:5001/api/request-logs').json()

    return render_template('dashboard.html', 
                           username=session['username'],
                           login_attempts=login_attempts,
                           unauthorized_access=unauthorized_access,
                           authentication_transactions=authentication_transactions,
                           ddos_logs=ddos_logs,
                           request_logs=request_logs)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')

@app.route('/api/login-attempts')
def get_login_attempts():
    return jsonify(parse_login_attempts(os.path.join(LOG_DIR, 'login_attempts.log')))

@app.route('/api/unauthorized-access')
def get_unauthorized_access():
    return jsonify(parse_unauthorized_access(os.path.join(LOG_DIR, 'unauthorized_access.log')))

@app.route('/api/authentication-transactions')
def get_authentication_transactions():
    transactions = []
    try:
        with open(os.path.join(LOG_DIR, 'authentication_transactions.log'), 'r') as file:
            for line in file:
                parts = line.strip().split(' ')
                timestamp, status, message = parts[0], parts[1], ' '.join(parts[2:])
                transactions.append({'timestamp': timestamp, 'status': status, 'message': message})
    except FileNotFoundError:
        transactions.append({'timestamp': '', 'status': '', 'message': 'Log file not found'})
    return jsonify(transactions)

@app.route('/api/ddos-logs')
def get_ddos_logs():
    ddos_log_file = r'D:\Major Project\login\request_app.log'
    logs = []

    log_pattern = re.compile(
        r"\[(.*?)\] "                           
        r"Sender IP: (.*?), "                    
        r"Receiver IP: (.*?), "                  
        r"URL: (.*?), "                          
        r"Method: (.*?), "                       
        r"UA: (.*?), "                           
        r"Status: (\d+)"                         
    )

    try:
        with open(ddos_log_file, 'r') as file:
            for line in file:
                line = line.strip()

                match = log_pattern.match(line)
                if match:
                    timestamp, sender_ip, receiver_ip, url, method, ua, status = match.groups()

                    logs.append({
                        "timestamp": timestamp,
                        "sender_ip": sender_ip,
                        "receiver_ip": receiver_ip,
                        "url": url,
                        "method": method,
                        "ua": ua,       
                        "status": status  
                    })
                else:
                    print(f"Skipping malformed line: {line}")
                    
    except FileNotFoundError:
        return jsonify({"error": "DDoS log file not found."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify(logs)    

@app.route('/api/request-logs')
def get_request_logs():
    return jsonify(parse_request_logs(REQUEST_LOG_FILE))

@app.route('/get_encrypted', methods=['GET'])
def get_encrypted():
    encrypted_msg = encrypt_message(SECRET_MESSAGE)
    with open("sent_encrypted.log", "a") as log:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log.write(f"[{timestamp}] Sent encrypted message: {encrypted_msg}\n")
    return jsonify({"encrypted_message": encrypted_msg})

@app.route('/send_to_auth_server', methods=['GET'])
def send_to_auth_server():
    try:
        encrypted_msg = encrypt_message(SECRET_MESSAGE)
        response = requests.get('http://127.0.0.1:5000/receive_encrypted', params={'message': encrypted_msg})
        with open("received_response.log", "a") as log:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log.write(f"[{timestamp}] Response from auth server: {response.json()}\n")
        return jsonify({
            "status": "Encrypted message sent and response received",
            "auth_server_response": response.json()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
