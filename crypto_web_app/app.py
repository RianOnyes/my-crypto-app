from flask import Flask, render_template, request, send_file, jsonify
import io
import os
import sqlite3
import base64
from datetime import datetime
# Library Kriptografi Lengkap
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
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
        print(f"Log Error: {e}")

# --- HELPER: Membuat Kunci AES dari Password Manual ---
def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

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
    except:
        return jsonify({'status': 'error'})

# 1. BUAT KUNCI (RSA Saja - Tanpa Password Key biar user ga bingung)
@app.route('/api/generate_keys', methods=['POST'])
def generate_keys():
    # Kita buat Private Key 'Polos' karena keamanan lapis 2 nanti ada di Password File
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() # Tidak dikunci password, karena nanti file yang dikunci password
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

# 2. ENKRIPSI (GABUNGAN 2 METODE)
@app.route('/api/encrypt_dual', methods=['POST'])
def encrypt_dual():
    try:
        file = request.files['file']
        pub_key_str = request.form['public_key'] # METODE 1: RSA
        password = request.form['password']      # METODE 2: PASSWORD MANUAL
        
        if not file or not pub_key_str or not password:
            return "Data tidak lengkap!", 400

        # A. Siapkan Bumbu (Salt) Acak
        salt = os.urandom(16)
        
        # B. Ubah Password Manual User menjadi Kunci Enkripsi (AES)
        # Kunci ini dibuat dari campuran Password + Salt
        aes_key = derive_key_from_password(password, salt)
        fernet = Fernet(aes_key)
        
        # C. Enkripsi File pakai Password tadi
        file_data = file.read()
        encrypted_file_data = fernet.encrypt(file_data)
        
        # D. Enkripsi "Salt" pakai Public Key (RSA)
        # Kenapa? Supaya orang yang tidak punya Private Key tidak bisa tahu "bumbu" passwordnya
        public_key = serialization.load_pem_public_key(pub_key_str.encode())
        encrypted_salt = public_key.encrypt(
            salt,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # E. Gabungkan: [Panjang Salt] + [Salt Terenkripsi RSA] + [File Terenkripsi Password]
        final_data = len(encrypted_salt).to_bytes(4, 'big') + encrypted_salt + encrypted_file_data
        
        log_history(file.filename, "Enkripsi Dual Layer")

        return send_file(
            io.BytesIO(final_data),
            as_attachment=True,
            download_name=f"{file.filename}.secure",
            mimetype='application/octet-stream'
        )

    except Exception as e:
        return f"Error: {str(e)}", 500

# 3. DEKRIPSI (WAJIB 2 METODE)
@app.route('/api/decrypt_dual', methods=['POST'])
def decrypt_dual():
    try:
        file = request.files['file']
        priv_key_str = request.form['private_key'] # SYARAT 1: Punya Kunci
        password = request.form['password']        # SYARAT 2: Tahu Password
        
        if not file or not priv_key_str or not password:
            return "File, Kunci, dan Password wajib diisi!", 400

        # Baca File
        full_data = file.read()
        
        # Pisahkan Bagian-bagiannya
        salt_len = int.from_bytes(full_data[:4], 'big')
        encrypted_salt = full_data[4:4+salt_len]
        encrypted_file_data = full_data[4+salt_len:]
        
        # TAHAP 1: Buka Kunci RSA untuk dapatkan "Bumbu" (Salt)
        try:
            private_key = serialization.load_pem_private_key(priv_key_str.encode(), password=None)
            salt = private_key.decrypt(
                encrypted_salt,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception:
            return "GAGAL TAHAP 1: Private Key Anda Salah/Tidak Cocok!", 403

        # TAHAP 2: Gunakan Password Manual + Salt untuk buka file
        try:
            aes_key = derive_key_from_password(password, salt)
            fernet = Fernet(aes_key)
            original_file_data = fernet.decrypt(encrypted_file_data)
        except Exception:
            return "GAGAL TAHAP 2: Private Key Benar, tapi PASSWORD ANDA SALAH!", 403
        
        log_history(file.filename, "Dekripsi Sukses")
        
        return send_file(
            io.BytesIO(original_file_data),
            as_attachment=True,
            download_name="file_terbuka.pdf",
            mimetype='application/pdf'
        )
        
    except Exception as e:
        return f"Error Sistem: {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=True)
