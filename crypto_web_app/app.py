from flask import Flask, render_template, request, send_file, jsonify
import io
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

app = Flask(__name__)

# --- LOGIC ---

@app.route('/')
def index():
    return render_template('index.html')

# 1. GENERATE KEYS (Sekarang dengan Password!)
@app.route('/api/generate_keys', methods=['POST'])
def generate_keys():
    data = request.json
    passphrase = data.get('password')  # Password dari user untuk mengunci Private Key
    
    if not passphrase:
        return jsonify({'status': 'error', 'message': 'Password wajib diisi!'})

    # Buat kunci RSA
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

# 2. ENKRIPSI FILE (PDF -> .SECURE)
@app.route('/api/encrypt_file', methods=['POST'])
def encrypt_file():
    try:
        # Ambil file dan public key dari form
        file = request.files['file']
        pub_key_str = request.form['public_key']
        
        if not file or not pub_key_str:
            return "Data tidak lengkap", 400

        # Load Public Key
        public_key = serialization.load_pem_public_key(pub_key_str.encode())
        
        # 1. Buat Kunci AES (Session Key)
        aes_key = Fernet.generate_key()
        fernet = Fernet(aes_key)
        
        # 2. Baca isi file PDF & Enkripsi pakai AES
        file_data = file.read()
        encrypted_file_data = fernet.encrypt(file_data)
        
        # 3. Enkripsi Kunci AES pakai RSA
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 4. Gabungkan (Panjang Kunci + Kunci Terenkripsi + File Terenkripsi)
        # Kita simpan panjang kunci di 4 byte pertama supaya bisa dipisahkan nanti
        final_data = len(encrypted_aes_key).to_bytes(4, 'big') + encrypted_aes_key + encrypted_file_data
        
        # Kirim balik sebagai file download
        return send_file(
            io.BytesIO(final_data),
            as_attachment=True,
            download_name=f"{file.filename}.secure",
            mimetype='application/octet-stream'
        )

    except Exception as e:
        return f"Error: {str(e)}", 500

# 3. DEKRIPSI FILE (.SECURE -> PDF)
@app.route('/api/decrypt_file', methods=['POST'])
def decrypt_file():
    try:
        file = request.files['file']
        priv_key_str = request.form['private_key']
        passphrase = request.form['password'] # Password untuk membuka Private Key
        
        if not file or not priv_key_str or not passphrase:
            return "Data tidak lengkap", 400

        # Baca semua data file .secure
        full_data = file.read()
        
        # Pisahkan komponen (Panjang Kunci | Kunci AES | Isi File)
        key_len = int.from_bytes(full_data[:4], 'big')
        encrypted_aes_key = full_data[4:4+key_len]
        encrypted_file_data = full_data[4+key_len:]
        
        # 1. Buka Private Key menggunakan Password User
        private_key = serialization.load_pem_private_key(
            priv_key_str.encode(),
            password=passphrase.encode()
        )
        
        # 2. Dekripsi Kunci AES
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 3. Dekripsi Isi File
        fernet = Fernet(aes_key)
        original_file_data = fernet.decrypt(encrypted_file_data)
        
        # Kembalikan file asli (asumsikan PDF, tapi bisa apa saja)
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
