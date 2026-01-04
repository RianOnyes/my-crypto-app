from flask import Flask, render_template, request, send_file, jsonify
import io
import os
import sqlite3
from datetime import datetime
# Library Kriptografi Wajib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

app = Flask(__name__)

# --- DATABASE SETUP ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'database.db')

def init_db():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS history
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                          filename TEXT, 
                          action TEXT, 
                          timestamp TEXT)''')
            conn.commit()
    except Exception as e:
        print(f"Error Database: {e}")

init_db()

def log_history(filename, action):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            waktu = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute("INSERT INTO history (filename, action, timestamp) VALUES (?, ?, ?)", 
                      (filename, action, waktu))
            conn.commit()
    except Exception as e:
        print(f"Gagal log: {e}")

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/get_history')
def get_history():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM history ORDER BY id DESC")
            return jsonify([dict(row) for row in c.fetchall()])
    except:
        return jsonify([])

@app.route('/api/clear_history', methods=['POST'])
def clear_history():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("DELETE FROM history")
            conn.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error'})

# --- 1. BUAT KUNCI (Dengan Password) ---
@app.route('/api/generate_keys', methods=['POST'])
def generate_keys():
    data = request.json
    passphrase = data.get('password') # Password Tahap 2
    
    if not passphrase:
        return jsonify({'status': 'error', 'message': 'Password wajib diisi!'})

    # Buat Kunci RSA 2048-bit
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # Kunci Privat diproteksi Password
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

# --- 2. ENKRIPSI (Pengirim) ---
@app.route('/api/encrypt_file', methods=['POST'])
def encrypt_file():
    try:
        file = request.files['file']
        pub_key_str = request.form['public_key']
        
        if not file or not pub_key_str:
            return "File dan Public Key wajib ada", 400

        log_history(file.filename, "Enkripsi RSA")

        # Load Public Key
        public_key = serialization.load_pem_public_key(pub_key_str.encode())
        
        # Buat Session Key (AES)
        aes_key = Fernet.generate_key()
        fernet = Fernet(aes_key)
        
        # Enkripsi Konten File
        file_data = file.read()
        encrypted_file_data = fernet.encrypt(file_data)
        
        # Enkripsi Session Key dengan RSA
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Gabungkan Metadata + Key + Data
        final_data = len(encrypted_aes_key).to_bytes(4, 'big') + encrypted_aes_key + encrypted_file_data
        
        return send_file(
            io.BytesIO(final_data),
            as_attachment=True,
            download_name=f"{file.filename}.secure",
            mimetype='application/octet-stream'
        )

    except Exception as e:
        return f"Error Enkripsi: {str(e)}", 500

# --- 3. DEKRIPSI (2 TAHAPAN: Key + Password) ---
@app.route('/api/decrypt_file', methods=['POST'])
def decrypt_file():
    try:
        file = request.files['file']
        priv_key_str = request.form['private_key'] # Tahap 1
        passphrase = request.form['password']      # Tahap 2
        
        if not file or not priv_key_str or not passphrase:
            return "Data tidak lengkap! Harap isi Kunci dan Password.", 400

        # Baca struktur file .secure
        full_data = file.read()
        key_len = int.from_bytes(full_data[:4], 'big')
        encrypted_aes_key = full_data[4:4+key_len]
        encrypted_file_data = full_data[4+key_len:]
        
        # PROSES VALIDASI TAHAP 1 & 2
        try:
            private_key = serialization.load_pem_private_key(
                priv_key_str.encode(),
                password=passphrase.encode() # Validasi Password disini
            )
        except ValueError:
            return "GAGAL TAHAP 2: Password Anda Salah!", 403
        except Exception:
            return "GAGAL TAHAP 1: Private Key tidak valid!", 403

        # Jika lolos, lanjut dekripsi
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
        
        log_history(file.filename, "Dekripsi Sukses")
        
        return send_file(
            io.BytesIO(original_file_data),
            as_attachment=True,
            download_name="file_terbuka.pdf", # Asumsi PDF
            mimetype='application/pdf'
        )
        
    except Exception as e:
        return f"Error Sistem: {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=True)
