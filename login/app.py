import os
import json
from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response, session
from datetime import datetime
from crypto_utils import decrypt_message

app = Flask(__name__)
app.secret_key = 'super_secret_key'

SESSION_META_FILE = os.path.join(os.getcwd(), 'session_metadata.json')


def load_users():
        with open('users.json') as f:
            return json.load(f)


def load_session_metadata():
        try:
            if os.path.exists(SESSION_META_FILE):
                with open(SESSION_META_FILE, 'r') as f:
                    return json.load(f)
            return {}
        except json.JSONDecodeError:
            return {}


def save_session_metadata(metadata):
        try:
            with open(SESSION_META_FILE, 'w') as f:
                json.dump(metadata, f, indent=4)
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            print(f"[ERROR] Saving session metadata: {e}")


def log_file(filename, message):
        try:
            log_path = os.path.join(os.getcwd(), filename)
            with open(log_path, 'a') as f:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                full_message = f"[{timestamp}] {message}\n"
                f.write(full_message)
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            print(f"[ERROR] Logging to {filename}: {e}")


def log_unauthorized_access(message):
        log_file("unauthorized_access.log", message)


def log_hijack_alert(message):
        log_file("hijack_alerts.log", message)


def log_auth_transaction(message, status="info"):
        log_file("authentication_transactions.log", f"[{status.upper()}] {message}")


def auto_logout(username, reason="Session hijack or unauthorized access"):
        try:
            metadata = load_session_metadata()
            if username in metadata:
                del metadata[username]
                save_session_metadata(metadata)

            session.pop('username', None)
            log_hijack_alert(f"[FORCE LOGOUT] User {username} was logged out. Reason: {reason}")
        except Exception as e:
            print(f"[ERROR] Auto logout failed: {e}")
        return make_response("Session invalidated due to security reasons. Please login again.", 403)


@app.route('/')
def home():
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
        error = None
        if request.method == 'POST':
            users = load_users()
            username = request.form['username']
            password = request.form['password']
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            suspicious = any(x in username.lower() for x in ["'", '"', " or ", "--", ";", "/*", "xp_"])
            log_file("login_attempts.log", f"IP: {request.remote_addr}, Username: {username}, SQLi Suspected: {suspicious}")

            if username not in users or users[username] != password:
                error = "Invalid username or password"
                log_unauthorized_access(f"Failed login. IP: {request.remote_addr}, Username: {username}")
                return render_template('login.html', error=error)

            session['username'] = username

            metadata = load_session_metadata()
            metadata[username] = {
                "ip": request.remote_addr,
                "user_agent": request.headers.get('User-Agent'),
                "timestamp": timestamp
            }
            save_session_metadata(metadata)

            return redirect(url_for('protected'))

        return render_template('login.html', error=error)


@app.route('/protected')
def protected():
        username = session.get('username')
        if not username:
            log_unauthorized_access(f"[UNAUTH ACCESS] Attempt to access /protected without login. "
                                    f"IP: {request.remote_addr}, UA: {request.headers.get('User-Agent')}")
            return redirect(url_for('login'))

        metadata = load_session_metadata()
        session_data = metadata.get(username)

        if not session_data:
            log_hijack_alert(f"[MISSING SESSION] No session metadata found for user {username}. "
                            f"Possible tampering or session corruption. IP: {request.remote_addr}")
            return auto_logout(username, "Session metadata missing")

        current_ip = request.remote_addr
        current_ua = request.headers.get('User-Agent')

        if session_data.get("ip") != current_ip or session_data.get("user_agent") != current_ua:
            log_hijack_alert(
                f"[HIJACK DETECTED] User: {username}\n"
                f"Expected IP: {session_data.get('ip')}, Actual IP: {current_ip}\n"
                f"Expected UA: {session_data.get('user_agent')}, Actual UA: {current_ua}\n"
                f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            return auto_logout(username, "Session hijack detected")

        return f"<h1>Welcome to the protected page, {username}!</h1>"


@app.route('/log', methods=['POST', 'GET'])
def log_request_details():
        sender_ip = request.remote_addr
        receiver_ip = request.host.split(":")[0]
        method = request.method
        url = request.url
        user_agent = request.headers.get('User-Agent')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        log_file("request_app.log", f"Sender IP: {sender_ip}, Receiver IP: {receiver_ip}, "
                                    f"URL: {url}, Method: {method}, UA: {user_agent}, Status: 204")

        log_file("request_logs.txt", f"{sender_ip} => {url} ({method}) — UA: {user_agent}")

        return '', 204


@app.route('/auth_logs')
def view_auth_logs():
        try:
            with open("authentication_transactions.log", "r") as f:
                logs = f.readlines()[-50:]
        except FileNotFoundError:
            logs = ["No logs available."]
        return render_template("auth_logs.html", logs=logs)


@app.route('/receive_encrypted', methods=['GET', 'POST'])
def receive_encrypted():
        try:
            
            if request.method == 'GET':
                encrypted_msg = request.args.get('message')
                sender = request.args.get('sender', 'unknown')
            else:
                data = request.get_json(force=True)
                encrypted_msg = data.get('encrypted', '')
                sender = data.get('sender', 'unknown')

            if not encrypted_msg:
                log_auth_transaction(f"[MISSING] No encrypted message received from IP {request.remote_addr}", "warning")
                return jsonify({"error": "Missing encrypted message"}), 400

            try:
                decrypted_msg = decrypt_message(encrypted_msg)
            except Exception as decryption_error:
                log_auth_transaction(
                    f"[MITM SUSPECTED] Decryption failed from {request.remote_addr} (Sender: {sender}). "
                    f"Payload: {encrypted_msg} | Error: {str(decryption_error)}",
                    "mitm"
                )
                return jsonify({"status": "error", "message": "Decryption failed", "details": str(decryption_error)}), 500

            if decrypted_msg == "AUTH_KASHYAPA":
                log_auth_transaction(f"[AUTH OK] Valid message from {request.remote_addr} (Sender: {sender})", "success")
                return jsonify({"status": "success", "message": "Authentication successful", "key": "SOME_SECRET_KEY"})
            else:
                log_auth_transaction(
                    f"[MITM SUSPECTED] Invalid decrypted message from {request.remote_addr} (Sender: {sender}). "
                    f"Decrypted: {decrypted_msg} | Raw: {encrypted_msg}",
                    "mitm"
                )
                return jsonify({"status": "failed", "message": "Invalid authentication message"}), 403

        except Exception as e:
            log_auth_transaction(
                f"[FATAL ERROR] Exception during auth message processing from {request.remote_addr}: {str(e)}",
                "error"
            )
            return jsonify({"error": "Server error", "details": str(e)}), 500


if __name__ == '__main__':
        app.run(debug=True, host='0.0.0.0', port=5000)
