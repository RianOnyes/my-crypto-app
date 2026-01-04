from flask import Flask, render_template, request, send_file, jsonify
import io
import os
import sqlite3
from datetime import datetime
from pypdf import PdfReader, PdfWriter # Kita pakai ini untuk standar PDF

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
                          unique_code_hint TEXT,
                          timestamp TEXT)''')
            conn.commit()
    except Exception as e:
        print(f"Error Database: {e}")

init_db()

def log_history(filename, code):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            waktu = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # Kita simpan 3 huruf pertama kode sebagai "Hint" (biar admin tau, tapi ga tau fullnya)
            hint = f"{code[:3]}***" if len(code) > 3 else "***"
            c.execute("INSERT INTO history (filename, action, unique_code_hint, timestamp) VALUES (?, ?, ?, ?)", 
                      (filename, "Enkripsi PDF", hint, waktu))
            conn.commit()
    except Exception as e:
        print(f"Gagal log: {e}")

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/process_pdf', methods=['POST'])
def process_pdf():
    try:
        # 1. Ambil File & Kode Unik
        file = request.files['file']
        unique_code = request.form['unique_code'] # Ini password aslinya
        
        if not file or not unique_code:
            return "File PDF dan Kode Unik wajib diisi!", 400
            
        # 2. Proses Enkripsi Standar PDF
        input_pdf = PdfReader(file)
        output_pdf = PdfWriter()
        
        # Salin halaman
        for page in input_pdf.pages:
            output_pdf.add_page(page)
            
        # 3. Kunci PDF menggunakan Kode Unik tersebut
        output_pdf.encrypt(unique_code)
        
        # 4. Simpan ke Buffer (Memori) untuk didownload
        output_buffer = io.BytesIO()
        output_pdf.write(output_buffer)
        output_buffer.seek(0)
        
        # 5. Catat di Riwayat
        log_history(file.filename, unique_code)
        
        return send_file(
            output_buffer,
            as_attachment=True,
            download_name=f"SECURE_{file.filename}",
            mimetype='application/pdf'
        )

    except Exception as e:
        return f"Gagal memproses. Pastikan file adalah PDF valid. Error: {str(e)}", 500

# --- API HISTORY ---
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

if __name__ == '__main__':
    app.run(debug=True)
