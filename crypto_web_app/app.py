from flask import Flask, render_template, request, send_file, jsonify
import io
import os
import sqlite3
import base64
from datetime import datetime
# Library untuk Metode 1 (Custom RSA+AES)
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
# Library untuk Metode 2 (PDF Standard)
from pypdf import PdfReader, PdfWriter

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
                          method TEXT, 
                          timestamp TEXT)''')
            conn.commit()
    except Exception as e:
        print(f"Error Database: {e}")

init_db()

def log_history(filename, method):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            waktu = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute("INSERT INTO history (filename, method, timestamp) VALUES (?, ?, ?)", 
                      (filename, method, waktu))
            conn.commit()
    except: pass

# --- HELPER METODE 1: AES Key dari Password ---
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000,
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
    except: return jsonify([])

@app.route('/api/clear_history', methods=['POST'])
def clear_history():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c.execute("DELETE FROM history"); conn.commit()
        return jsonify({'status': 'success'})
    except: return jsonify({'status': 'error'})

# --- LOGIKA METODE 1: Generate Key ---
@app.route('/api/generate_keys', methods=['POST'])
def generate_keys():
    # Buat kunci RSA polos (Password user akan dipakai di file, bukan di kunci ini)
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
    return jsonify({'status': 'success', 'private_key': pem_priv.decode('utf-8'), 'public_key': pem_pub.decode('utf-8')})

# --- LOGIKA METODE 1: Enkripsi & Dekripsi (RSA + AES) ---
@app.route('/api/method1_encrypt', methods=['POST'])
def method1_encrypt():
    try:
        file = request.files['file']
        pub_key_str = request.form['public_key']
        password = request.form['password']
        
        salt = os.urandom(16) # Bumbu acak
        aes_key = derive_key(password, salt) # Password jadi kunci AES
        fernet = Fernet(aes_key)
        
        # Kata-kata diacak total disini (jadi byte acak)
        encrypted_data = fernet.encrypt(file.read())
        
        # Kunci bumbu (salt) pakai RSA
        public_key = serialization.load_pem_public_key(pub_key_str.encode())
        encrypted_salt = public_key.encrypt(
            salt, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        
        final_data = len(encrypted_salt).to_bytes(4, 'big') + encrypted_salt + encrypted_data
        log_history(file.filename, "Metode 1 (RSA+Pass)")
        
        return send_file(io.BytesIO(final_data), as_attachment=True, download_name=f"{file.filename}.secure", mimetype='application/octet-stream')
    except Exception as e: return f"Error: {e}", 500

@app.route('/api/method1_decrypt', methods=['POST'])
def method1_decrypt():
    try:
        file = request.files['file']
        priv_key_str = request.form['private_key']
        password = request.form['password']
        
        full_data = file.read()
        salt_len = int.from_bytes(full_data[:4], 'big')
        encrypted_salt = full_data[4:4+salt_len]
        encrypted_file = full_data[4+salt_len:]
        
        # Tahap 1: Buka Salt pakai Key File
        try:
            private_key = serialization.load_pem_private_key(priv_key_str.encode(), password=None)
            salt = private_key.decrypt(encrypted_salt, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        except: return "Kunci Private Salah/Tidak Cocok!", 403

        # Tahap 2: Buka File pakai Password
        try:
            aes_key = derive_key(password, salt)
            fernet = Fernet(aes_key)
            original_data = fernet.decrypt(encrypted_file)
        except: return "Kunci Benar, TAPI PASSWORD SALAH!", 403
        
        return send_file(io.BytesIO(original_data), as_attachment=True, download_name="hasil_decrypt_metode1.pdf", mimetype='application/pdf')
    except Exception as e: return f"Error: {e}", 500


# --- LOGIKA METODE 2: PDF Standard (Password Only) ---
@app.route('/api/method2_encrypt', methods=['POST'])
def method2_encrypt():
    try:
        file = request.files['file']
        password = request.form['password']
        
        input_pdf = PdfReader(file)
        output_pdf = PdfWriter()
        
        for page in input_pdf.pages:
            output_pdf.add_page(page)
            
        # Enkripsi PDF Standard (AES-128)
        output_pdf.encrypt(password)
        
        output_buffer = io.BytesIO()
        output_pdf.write(output_buffer)
        output_buffer.seek(0)
        
        log_history(file.filename, "Metode 2 (PDF Pass)")
        
        return send_file(output_buffer, as_attachment=True, download_name=f"PROTECTED_{file.filename}", mimetype='application/pdf')
    except Exception as e: return f"Gagal. Pastikan file PDF valid. {e}", 500

if __name__ == '__main__':
    app.run(debug=True)
