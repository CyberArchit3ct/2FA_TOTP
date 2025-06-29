import time
import hmac
import base64
import struct
import hashlib

def get_totp(secret, interval=30, digits=6):
    key = base64.b32decode(secret.upper())
    counter = int(time.time()) // interval
    msg = struct.pack(">Q", counter)
    hmac_hash = hmac.new(key, msg, hashlib.sha1).digest()
    offset = hmac_hash[-1] & 0x0F
    truncated_hash = hmac_hash[offset:offset + 4]
    code = struct.unpack(">I", truncated_hash)[0] & 0x7FFFFFFF
    totp = code % (10 ** digits)
    return str(totp).zfill(digits)

secret_key = input("Enter your secret key:") #"JBSWY3DPEHPK3PXP"
print("Your TOTP is:", get_totp(secret_key))
