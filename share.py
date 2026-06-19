import os
import sys
import socket
import json
import base64
import hashlib
import random
import string
import urllib.parse
import webbrowser
from http.server import SimpleHTTPRequestHandler, HTTPServer
import threading

GITHUB_PAGES_URL = "https://itsmarwan.github.io/DirectConnect/"

def derive_key(password, salt):
    key = password + salt
    return hashlib.sha256(key.encode()).digest()

def encrypt_data(data_str, password):
    salt = "".join(random.choices(string.ascii_letters + string.digits, k=8))
    key = derive_key(password, salt)
    
    data_bytes = data_str.encode('utf-8')
    encrypted_bytes = bytearray()
    
    for i, byte in enumerate(data_bytes):
        keystream_byte = hashlib.sha256(key + i.to_bytes(4, 'big')).digest()[0]
        encrypted_bytes.append(byte ^ keystream_byte)
        
    payload = salt + base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')
    return payload

class CORSHTTPRequestHandler(SimpleHTTPRequestHandler):
    file_to_serve = None
    original_filename = ""
    auth_token = ""

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        expected_path = f"/{self.auth_token}"
        
        if parsed_url.path != expected_path:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
            return

        if not self.file_to_serve or not os.path.exists(self.file_to_serve):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"File not available")
            return

        try:
            with open(self.file_to_serve, 'rb') as f:
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename="{self.original_filename}"')
                self.send_header('Content-Length', str(os.path.getsize(self.file_to_serve)))
                self.end_headers()
                
                buffer_size = 64 * 1024
                while True:
                    data = f.read(buffer_size)
                    if not data:
                        break
                    self.wfile.write(data)
        except Exception as e:
            print(f"\nError serving file: {e}")

def run_server(port, token, filepath, filename):
    CORSHTTPRequestHandler.file_to_serve = filepath
    CORSHTTPRequestHandler.original_filename = filename
    CORSHTTPRequestHandler.auth_token = token
    
    server_address = ('127.0.0.1', port)
    httpd = HTTPServer(server_address, CORSHTTPRequestHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()

def main():
    print("            🎯 DirectConnect                ")
    
    password = ""
    while not password:
        password = input("Enter session encryption password: ").strip()
    
    filepath = ""
    while not filepath:
        raw_path = input("Drag & drop file here or enter filepath: ").strip()
        clean_path = raw_path.strip('"').strip("'")
        if os.path.exists(clean_path) and os.path.isfile(clean_path):
            filepath = clean_path
        else:
            print("Invalid file! Please try again.")

    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)
    
    port = random.randint(15000, 25000)
    token = "".join(random.choices(string.ascii_letters + string.digits, k=16))
    
    local_info = {
        "port": port,
        "token": token,
        "filename": filename,
        "size": filesize
    }
    
    local_info_json = json.dumps(local_info)
    encrypted_payload = encrypt_data(local_info_json, password)
    
    sender_url = f"{GITHUB_PAGES_URL}#sender?p={encrypted_payload}"
    
    print("\n[DirectConnect] Starting file provider on localhost...")
    server_thread = threading.Thread(target=run_server, args=(port, token, filepath, filename), daemon=True)
    server_thread.start()
    
    print("[DirectConnect] Opening browser to initialize direct P2P pipeline...")
    webbrowser.open(sender_url)
    
    print("\n" + "="*50)
    print("Keep this companion tool running during file transfer!")
    print("Press Ctrl+C to terminate the link stream.")
    print("="*50)

    try:
        while True:
            server_thread.join(timeout=1.0)
    except KeyboardInterrupt:
        print("\nShutting down stream. Goodbye!")

if __name__ == "__main__":
    main()
