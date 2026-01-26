"""
BugTraceAI Reporting Lab
Port: 5005

PURPOSE: SIMPLE TARGET (2 URLs)
- Designed for Reporting Validation and Traceability.
- Minimal noise to verify PoCs, screenshots, and reproduction steps in reports.
"""
from flask import Flask, request, send_from_directory
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        filename = file.filename
        # Filtro de mentira: bloqueamos .php y .py
        if filename.endswith('.php') or filename.endswith('.py'):
            return "Error: Restricted file type!", 403
        
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        return f"Success! File uploaded to uploads/{filename}"
    
    return '''
    <html>
      <body>
        <form method="POST" enctype="multipart/form-data" id="upload_lab">
          <input type="file" name="file">
          <input type="submit">
        </form>
      </body>
    </html>
    '''

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

if __name__ == '__main__':
    app.run(port=5005)
