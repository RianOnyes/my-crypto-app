from flask import Flask, render_template, request, send_file, jsonify
import io
import os
import sqlite3
from datetime import datetime
# Import pustaka baru untuk PDF
from pypdf import PdfReader, PdfWriter

app = Flask(__name__)

# --- DATABASE SETUP (TETAP SAMA) ---
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
        return jsonify({'status': 'error', 'message': str(e)})

# --- LOGIKA BARU: STANDARD PDF ENCRYPTION ---

@app.route('/api/encrypt_pdf', methods=['POST'])
def encrypt_pdf():
    try:
        # 1. Ambil File dan Password dari Form
        file = request.files['file']
        password = request.form['password']
        
        if not file or not password:
            return "File dan Password wajib diisi!", 400
            
        # 2. Baca PDF Asli
        input_pdf = PdfReader(file)
        output_pdf = PdfWriter()
        
        # 3. Salin semua halaman ke PDF baru
        for page in input_pdf.pages:
            output_pdf.add_page(page)
            
        # 4. KUNCI PDF DENGAN PASSWORD (AES-128 standard)
        output_pdf.encrypt(password)
        
        # 5. Siapkan untuk download
        output_buffer = io.BytesIO()
        output_pdf.write(output_buffer)
        output_buffer.seek(0)
        
        # Catat di history
        log_history(file.filename, "PDF Protection")
        
        return send_file(
            output_buffer,
            as_attachment=True,
            # Nama file output jadi "namaasli_protected.pdf"
            download_name=f"{file.filename.replace('.pdf', '')}_protected.pdf",
            mimetype='application/pdf'
        )

    except Exception as e:
        return f"Gagal memproses PDF. Pastikan file adalah PDF valid. Error: {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=True)
