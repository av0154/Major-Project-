from flask import Flask, jsonify
from crypto_utils import encrypt_message

app = Flask(__name__)

@app.route('/get_encrypted', methods=['GET'])
def send_encrypted():
    message = "ServerSecureMsg"
    encrypted = encrypt_message(message)
    return jsonify({"encrypted_message": encrypted})

if __name__ == '__main__':
    app.run(port=5001)  

