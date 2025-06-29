import time
import hmac
import base64
import struct
import hashlib
import tkinter as tk

def get_totp(secret, interval=30, digits=6):
    try:
        key = base64.b32decode(secret.upper())
    except Exception:
        return "Invalid secret"
    counter = int(time.time()) // interval
    msg = struct.pack(">Q", counter)
    hmac_hash = hmac.new(key, msg, hashlib.sha1).digest()
    offset = hmac_hash[-1] & 0x0F
    truncated_hash = hmac_hash[offset:offset + 4]
    code = struct.unpack(">I", truncated_hash)[0] & 0x7FFFFFFF
    totp = code % (10 ** digits)
    return str(totp).zfill(digits)

def update_totp():
    secret = secret_entry.get().strip()
    if secret:
        totp = get_totp(secret)
        totp_label.config(text=f"TOTP: {totp}")
    else:
        totp_label.config(text="Please enter a secret key.")
    window.after(1000, update_totp)

window = tk.Tk()
window.title("TOTP Generator")
window.geometry("350x180")
window.resizable(False, False)

tk.Label(window, text="Enter Base32 Secret Key:").pack(pady=5)
secret_entry = tk.Entry(window, width=40)
secret_entry.pack()

totp_label = tk.Label(window, text="TOTP: ", font=("Helvetica", 18))
totp_label.pack(pady=15)

update_totp()
window.mainloop()
