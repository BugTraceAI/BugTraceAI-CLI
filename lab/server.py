import http.server
import os
import re

class UploadHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'''
                <html><body>
                <form method="POST" enctype="multipart/form-data" id="upload_lab">
                    <input type="file" name="file">
                    <input type="submit">
                </form>
                </body></html>
            ''')
        elif self.path.startswith('/uploads/'):
            filename = self.path.split('/')[-1]
            filepath = os.path.join('uploads', filename)
            if os.path.exists(filepath):
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                with open(filepath, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404)

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        boundary = self.headers['Content-Type'].split("boundary=")[-1].encode()
        parts = body.split(boundary)
        for part in parts:
            if b'filename="' in part:
                filename = re.findall(b'filename="(.+?)"', part)[0].decode()
                content = part.split(b'\r\n\r\n')[1].rsplit(b'\r\n--', 1)[0]
                os.makedirs('uploads', exist_ok=True)
                with open(os.path.join('uploads', filename), 'wb') as f:
                    f.write(content)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(f"Success! uploads/{filename}".encode())
                return
if __name__ == '__main__':
    http.server.HTTPServer(('127.0.0.1', 5006), UploadHandler).serve_forever()
