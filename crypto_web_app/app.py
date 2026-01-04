from flask import Flask, render_template, request, send_file, jsonify
import io
import os
import sqlite3
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

app = Flask(__name__)

# --- DATABASE SETUP ---
def init_db():
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        # Membuat tabel jika belum ada
        c.execute('''CREATE TABLE IF NOT EXISTS history
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                      filename TEXT, 
                      action TEXT, 
                      timestamp TEXT)''')
        conn.commit()

# Jalankan pembuatan database saat aplikasi mulai
init_db()

def log_history(filename, action):
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            waktu = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute("INSERT INTO history (filename, action, timestamp) VALUES (?, ?, ?)", 
                      (filename, action, waktu))
            conn.commit()
    except Exception as e:
        print(f"Gagal menyimpan history: {e}")

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/get_history')
def get_history():
    try:
        with sqlite3.connect('database.db') as conn:
            conn.row_factory = sqlite3.Row # Agar bisa akses nama kolom
            c = conn.cursor()
            c.execute("SELECT * FROM history ORDER BY id DESC") # Urutkan dari yang terbaru
            rows = c.fetchall()
            # Ubah ke format JSON list
            history_data = [dict(row) for row in rows]
            return jsonify(history_data)
    except Exception as e:
        return jsonify([])

@app.route('/api/generate_keys', methods=['POST'])
def generate_keys():
    data = request.json
    passphrase = data.get('password')
    
    if not passphrase:
        return jsonify({'status': 'error', 'message': 'Password wajib diisi!'})

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
    )
    
    pem_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return jsonify({
        'status': 'success',
        'private_key': pem_priv.decode('utf-8'),
        'public_key': pem_pub.decode('utf-8')
    })

@app.route('/api/encrypt_file', methods=['POST'])
def encrypt_file():
    try:
        file = request.files['file']
        pub_key_str = request.form['public_key']
        
        if not file or not pub_key_str:
            return "Data tidak lengkap", 400

        # --- SIMPAN KE HISTORY ---
        log_history(file.filename, "Enkripsi")
        
        public_key = serialization.load_pem_public_key(pub_key_str.encode())
        aes_key = Fernet.generate_key()
        fernet = Fernet(aes_key)
        
        file_data = file.read()
        encrypted_file_data = fernet.encrypt(file_data)
        
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        final_data = len(encrypted_aes_key).to_bytes(4, 'big') + encrypted_aes_key + encrypted_file_data
        
        return send_file(
            io.BytesIO(final_data),
            as_attachment=True,
            download_name=f"{file.filename}.secure",
            mimetype='application/octet-stream'
        )

    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/api/decrypt_file', methods=['POST'])
def decrypt_file():
    try:
        file = request.files['file']
        priv_key_str = request.form['private_key']
        passphrase = request.form['password']
        
        if not file or not priv_key_str or not passphrase:
            return "Data tidak lengkap", 400

        # --- SIMPAN KE HISTORY ---
        log_history(file.filename, "Dekripsi")

        full_data = file.read()
        key_len = int.from_bytes(full_data[:4], 'big')
        encrypted_aes_key = full_data[4:4+key_len]
        encrypted_file_data = full_data[4+key_len:]
        
        private_key = serialization.load_pem_private_key(
            priv_key_str.encode(),
            password=passphrase.encode()
        )
        
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        fernet = Fernet(aes_key)
        original_file_data = fernet.decrypt(encrypted_file_data)
        
        return send_file(
            io.BytesIO(original_file_data),
            as_attachment=True,
            download_name="decrypted_file.pdf",
            mimetype='application/pdf'
        )
        
    except ValueError:
        return "Password Salah! Private Key tidak bisa dibuka.", 403
    except Exception as e:
        return f"Gagal Dekripsi: {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=True)
