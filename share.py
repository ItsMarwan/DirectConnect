import os
import sys
import socket
import json
import hashlib
import random
import string
import urllib.parse
import webbrowser
from http.server import SimpleHTTPRequestHandler, HTTPServer
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

# Default production URL pointing to your GitHub Pages deployment
GITHUB_PAGES_URL = "https://itsmarwan.github.io/DirectConnect/"

# --- NATIVE WINDOWS DRAG AND DROP INTEGRATION VIA CTYPES ---
# Guaranteed safe pointer marshaling to avoid Access Violation / Truncation / NoneType crashes.
IS_WINDOWS = sys.platform == "win32"
drag_drop_handler = None

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes
    
    # Offsets and message values
    GWL_WNDPROC = -4
    WM_DROPFILES = 0x0233
    
    user32 = ctypes.windll.user32
    shell32 = ctypes.windll.shell32
    
    # Map correct size integer type matching pointer size to prevent NoneType conversion errors
    LRESULT_TYPE = ctypes.c_ssize_t if sys.maxsize > 2**32 else ctypes.c_long
    
    # 1. Properly set argtypes and restypes to prevent 64-bit pointer truncation!
    if sys.maxsize > 2**32:
        # x64 Hooking definitions
        user32.GetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.GetWindowLongPtrW.restype = ctypes.c_void_p
        
        user32.SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
        user32.SetWindowLongPtrW.restype = ctypes.c_void_p
        
        _GetWindowLong = user32.GetWindowLongPtrW
        _SetWindowLong = user32.SetWindowLongPtrW
    else:
        # x86 Hooking definitions
        user32.GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.GetWindowLongW.restype = ctypes.c_void_p
        
        user32.SetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
        user32.SetWindowLongW.restype = ctypes.c_void_p
        
        _GetWindowLong = user32.GetWindowLongW
        _SetWindowLong = user32.SetWindowLongW

    # Define accurate signatures for messaging and drops.
    user32.CallWindowProcW.argtypes = [ctypes.c_void_p, wintypes.HWND, ctypes.c_uint, wintypes.WPARAM, wintypes.LPARAM]
    user32.CallWindowProcW.restype = LRESULT_TYPE

    shell32.DragAcceptFiles.argtypes = [wintypes.HWND, wintypes.BOOL]
    shell32.DragAcceptFiles.restype = None
    
    shell32.DragQueryFileW.argtypes = [wintypes.WPARAM, ctypes.c_uint, wintypes.LPWSTR, ctypes.c_uint]
    shell32.DragQueryFileW.restype = ctypes.c_uint
    
    shell32.DragFinish.argtypes = [wintypes.WPARAM]
    shell32.DragFinish.restype = None

    # WNDPROC returns LRESULT (LRESULT_TYPE matches system architecture exactly)
    WNDPROC = ctypes.WINFUNCTYPE(LRESULT_TYPE, wintypes.HWND, ctypes.c_uint, wintypes.WPARAM, wintypes.LPARAM)
    
    class WindowsDragDrop:
        def __init__(self, root, callback):
            self.root = root
            self.callback = callback
            self.root.update_idletasks()
            self.hwnd = self.root.winfo_id()
            
            # Subclass the window
            self.old_wndproc = _GetWindowLong(self.hwnd, GWL_WNDPROC)
            self.new_wndproc = WNDPROC(self.wnd_proc)
            _SetWindowLong(self.hwnd, GWL_WNDPROC, ctypes.cast(self.new_wndproc, ctypes.c_void_p))
            
            shell32.DragAcceptFiles(self.hwnd, True)

        def wnd_proc(self, hwnd, msg, wp, lp):
            if msg == WM_DROPFILES:
                # IMPORTANT: We gather the data but do NOT call any tkinter methods here.
                # We just extract the raw string pointers.
                num_files = shell32.DragQueryFileW(wp, 0xFFFFFFFF, None, 0)
                file_list = []
                for i in range(num_files):
                    length = shell32.DragQueryFileW(wp, i, None, 0)
                    buf = ctypes.create_unicode_buffer(length + 1)
                    shell32.DragQueryFileW(wp, i, buf, length + 1)
                    file_list.append(buf.value)
                shell32.DragFinish(wp)
                
                # Schedule the callback in the MAIN thread using the event loop safely.
                # This bypasses the OS thread crash entirely.
                for f in file_list:
                    self.root.after_idle(self.safe_callback, f)
                return 0
            
            return user32.CallWindowProcW(self.old_wndproc, hwnd, msg, wp, lp)

        def safe_callback(self, filepath):
            # This runs on the Main Thread (GIL held), where it is safe to talk to Tkinter.
            self.callback(filepath)

def derive_key(password, salt):
    """Derive a simple key from password and salt using SHA-256."""
    key = password + salt
    return hashlib.sha256(key.encode()).digest()

def encrypt_data(data_str, password):
    """Encrypt metadata using a pure-Python SHA-256 keystream and output as Hex."""
    salt = "".join(random.choices(string.ascii_letters + string.digits, k=8))
    key = derive_key(password, salt)
    
    data_bytes = data_str.encode('utf-8')
    encrypted_bytes = bytearray()
    
    for i, byte in enumerate(data_bytes):
        keystream_byte = hashlib.sha256(key + i.to_bytes(4, 'big')).digest()[0]
        encrypted_bytes.append(byte ^ keystream_byte)
        
    return salt + encrypted_bytes.hex()

class CORSHTTPRequestHandler(SimpleHTTPRequestHandler):
    """An HTTP handler that supports CORS and modern Private Network Access headers."""
    file_to_serve = None
    original_filename = ""
    auth_token = ""

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        # CRITICAL: Bypasses browser 'Private Network Access' (PNA) blocks
        self.send_header('Access-Control-Allow-Private-Network', 'true')
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
            print(f"Error serving file: {e}")

class DirectConnectApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DirectConnect | by itsmarwan")
        self.root.geometry("540x520")
        self.root.resizable(False, False)
        self.root.configure(bg="#000000")
        
        self.filepath = ""
        self.server_thread = None
        self.httpd = None

        # Custom high-contrast theme styling
        self.color_bg = "#000000"
        self.color_card = "#0c0c0e"
        self.color_border = "#27272a"
        self.color_green = "#22c55e"
        self.color_text = "#ffffff"
        self.color_dim = "#a1a1aa"

        self.setup_ui()
        self.setup_icon()
        
        # Initialize native Drag & Drop if running on Windows
        if IS_WINDOWS:
            try:
                global drag_drop_handler
                drag_drop_handler = WindowsDragDrop(self.root, self.handle_dropped_file)
            except Exception as e:
                print(f"Could not hook native Windows Drag and Drop: {e}")

    def setup_icon(self):
        """Load favicon.png/icon.png from current working directory to serve as app icon."""
        for icon_name in ["favicon.png", "icon.png"]:
            if os.path.exists(icon_name):
                try:
                    icon_img = tk.PhotoImage(file=icon_name)
                    self.root.iconphoto(True, icon_img)
                    break
                except Exception as e:
                    print(f"Failed to load application window icon: {e}")

    def handle_dropped_file(self, filepath):
        """Process files dropped directly onto the window."""
        if filepath and os.path.exists(filepath) and os.path.isfile(filepath):
            self.filepath = filepath
            filename = os.path.basename(filepath)
            size_mb = os.path.getsize(filepath) / (1024 * 1024)
            self.lbl_file_status.configure(text=f"{filename} ({size_mb:.2f} MB)", fg=self.color_text)

    def setup_ui(self):
        # Header
        header_frame = tk.Frame(self.root, bg=self.color_bg, pady=15)
        header_frame.pack(fill="x", padx=20)
        
        lbl_title = tk.Label(header_frame, text="DIRECTCONNECT", font=("Consolas", 20, "bold"), fg=self.color_text, bg=self.color_bg)
        lbl_title.pack(anchor="w")
        
        lbl_subtitle = tk.Label(header_frame, text="BY ITSMARWAN • P2P COMPANION", font=("Consolas", 9, "bold"), fg=self.color_green, bg=self.color_bg)
        lbl_subtitle.pack(anchor="w")

        # Main Box container
        container = tk.Frame(self.root, bg=self.color_card, bd=1, relief="flat", highlightbackground=self.color_border, highlightthickness=1)
        container.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # STEP 1: Password Configuration
        step1_frame = tk.Frame(container, bg=self.color_card, pady=10)
        step1_frame.pack(fill="x", padx=15)
        
        lbl_pwd = tk.Label(step1_frame, text="1. SESSION PASSWORD", font=("Consolas", 10, "bold"), fg=self.color_dim, bg=self.color_card)
        lbl_pwd.pack(anchor="w", pady=(0, 5))
        
        self.entry_pwd = tk.Entry(step1_frame, bg="#18181b", fg=self.color_text, bd=0, insertbackground="white", highlightthickness=1, highlightbackground=self.color_border, highlightcolor=self.color_green, font=("Consolas", 11), show="•")
        self.entry_pwd.pack(fill="x", ipady=8)

        # STEP 2: File Selection
        step2_frame = tk.Frame(container, bg=self.color_card, pady=10)
        step2_frame.pack(fill="x", padx=15)
        
        lbl_file = tk.Label(step2_frame, text="2. SHARE TARGET (DRAG & DROP READY)", font=("Consolas", 10, "bold"), fg=self.color_dim, bg=self.color_card)
        lbl_file.pack(anchor="w", pady=(0, 5))
        
        file_select_frame = tk.Frame(step2_frame, bg=self.color_card)
        file_select_frame.pack(fill="x")
        
        self.btn_browse = tk.Button(file_select_frame, text="BROWSE", command=self.browse_file, bg=self.color_green, fg="#000000", activebackground="#16a34a", activeforeground="#000000", font=("Consolas", 9, "bold"), bd=0, padx=15, pady=8, cursor="hand2")
        self.btn_browse.pack(side="left")
        
        self.lbl_file_status = tk.Label(file_select_frame, text="Drag & drop file or click browse", font=("Consolas", 9), fg=self.color_dim, bg=self.color_card, anchor="w")
        self.lbl_file_status.pack(side="left", fill="x", expand=True, padx=10)

        # STEP 3: Start Stream Control
        step3_frame = tk.Frame(container, bg=self.color_card, pady=15)
        step3_frame.pack(fill="x", padx=15)
        
        self.btn_action = tk.Button(step3_frame, text="START P2P STREAM SERVER", command=self.toggle_server, bg=self.color_text, fg="#000000", activebackground=self.color_dim, font=("Consolas", 11, "bold"), bd=0, cursor="hand2")
        self.btn_action.pack(fill="x", ipady=10)

        # Display output status and share token details
        self.status_frame = tk.Frame(container, bg=self.color_card, pady=10)
        self.status_frame.pack(fill="both", expand=True, padx=15)
        
        self.lbl_status = tk.Label(self.status_frame, text="Offline", font=("Consolas", 10, "bold"), fg=self.color_dim, bg=self.color_card)
        self.lbl_status.pack(anchor="w")

        self.url_frame = tk.Frame(self.status_frame, bg=self.color_card)
        
        self.entry_url = tk.Entry(self.url_frame, bg="#18181b", fg=self.color_green, bd=0, highlightthickness=1, highlightbackground=self.color_border, font=("Consolas", 9), readonlybackground="#18181b")
        self.entry_url.pack(side="left", fill="x", expand=True, ipady=6)
        
        self.btn_copy = tk.Button(self.url_frame, text="COPY", command=self.copy_url, bg=self.color_border, fg=self.color_text, activebackground=self.color_dim, font=("Consolas", 8, "bold"), bd=0, padx=12, pady=6, cursor="hand2")
        self.btn_copy.pack(side="right", padx=(5, 0))

    def browse_file(self):
        selected = filedialog.askopenfilename()
        if selected:
            self.handle_dropped_file(selected)

    def toggle_server(self):
        if self.httpd is None:
            # Validate configuration parameters
            password = self.entry_pwd.get().strip()
            if not password:
                messagebox.showerror("Validation Error", "Please define a session security password.")
                return
            if not self.filepath or not os.path.exists(self.filepath):
                messagebox.showerror("Validation Error", "Please select a file to share.")
                return
            
            self.start_server(password)
        else:
            self.stop_server()

    def start_server(self, password):
        filename = os.path.basename(self.filepath)
        filesize = os.path.getsize(self.filepath)
        
        # Build network token endpoints
        port = random.randint(15000, 25000)
        token = "".join(random.choices(string.ascii_letters + string.digits, k=16))
        
        local_info = {
            "port": port,
            "token": token,
            "filename": filename,
            "size": filesize
        }
        
        # Cryptographic configuration
        local_info_json = json.dumps(local_info)
        encrypted_payload = encrypt_data(local_info_json, password)
        
        # Compile WebRTC initialization URL
        sender_url = f"{GITHUB_PAGES_URL}#sender?p={encrypted_payload}"
        
        # Fire up HTTP Server
        CORSHTTPRequestHandler.file_to_serve = self.filepath
        CORSHTTPRequestHandler.original_filename = filename
        CORSHTTPRequestHandler.auth_token = token
        
        try:
            self.httpd = HTTPServer(('127.0.0.1', port), CORSHTTPRequestHandler)
            self.server_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
            self.server_thread.start()
            
            # Update GUI States
            self.lbl_status.configure(text="Stream active • Exposing direct local channel", fg=self.color_green)
            self.btn_action.configure(text="STOP SHARE SYSTEM", bg="#ef4444", fg="#ffffff")
            self.entry_pwd.configure(state="disabled")
            self.btn_browse.configure(state="disabled")
            
            self.url_frame.pack(fill="x", pady=10)
            self.entry_url.configure(state="normal")
            self.entry_url.delete(0, tk.END)
            self.entry_url.insert(0, sender_url)
            self.entry_url.configure(state="readonly")
            
            # Fire local browser to bridge connection
            webbrowser.open(sender_url)
            
        except Exception as ex:
            messagebox.showerror("Server Error", f"Unable to initialize local socket: {ex}")
            self.stop_server()

    def stop_server(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
            
        self.lbl_status.configure(text="Offline", fg=self.color_dim)
        self.btn_action.configure(text="START P2P STREAM SERVER", bg=self.color_text, fg="#000000")
        self.entry_pwd.configure(state="normal")
        self.btn_browse.configure(state="normal")
        self.url_frame.pack_forget()
        
        self.entry_url.configure(state="normal")
        self.entry_url.delete(0, tk.END)
        self.entry_url.configure(state="readonly")

    def copy_url(self):
        url = self.entry_url.get()
        if url:
            self.root.clipboard_clear()
            self.root.clipboard_append(url)
            self.root.update()
            
            original_text = self.btn_copy.cget("text")
            self.btn_copy.configure(text="COPIED!", bg=self.color_green, fg="#000000")
            self.root.after(1500, lambda: self.btn_copy.configure(text=original_text, bg=self.color_border, fg=self.color_text))

def main():
    root = tk.Tk()
    app = DirectConnectApp(root)
    
    # Custom safety cleanup protocol
    def on_closing():
        app.stop_server()
        root.destroy()
        
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()