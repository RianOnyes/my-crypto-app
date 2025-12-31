from flask import Flask, render_template, request, jsonify
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

app = Flask(__name__)

# --- LOGIC ---
def gen_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_priv.decode('utf-8'), pem_pub.decode('utf-8')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/generate_keys', methods=['POST'])
def generate_keys():
    priv, pub = gen_rsa_keys()
    return jsonify({'private_key': priv, 'public_key': pub})

@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    try:
        # 1. Load Public Key
        pub_key_obj = serialization.load_pem_public_key(data['public_key'].encode())
        message = data['message']
        
        # 2. Hybrid Encrypt
        aes_key = Fernet.generate_key()
        fernet = Fernet(aes_key)
        enc_msg = fernet.encrypt(message.encode()) # AES encrypt message
        
        enc_aes_key = pub_key_obj.encrypt(         # RSA encrypt AES key
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return jsonify({
            'status': 'success',
            'enc_aes_key': base64.b64encode(enc_aes_key).decode('utf-8'),
            'ciphertext': enc_msg.decode('utf-8')
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    try:
        priv_key_obj = serialization.load_pem_private_key(data['private_key'].encode(), password=None)
        enc_aes_key = base64.b64decode(data['enc_aes_key'])
        ciphertext = data['ciphertext'].encode()
        
        # Decrypt AES Key using RSA
        aes_key = priv_key_obj.decrypt(
            enc_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt Message using AES
        fernet = Fernet(aes_key)
        original_msg = fernet.decrypt(ciphertext).decode('utf-8')
        
        return jsonify({'status': 'success', 'plaintext': original_msg})
    except Exception as e:
        return jsonify({'status': 'error', 'message': "Gagal Dekripsi! Kunci tidak cocok."})

if __name__ == '__main__':
    app.run(debug=True)