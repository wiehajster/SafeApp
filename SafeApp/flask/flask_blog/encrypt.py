from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import random
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

def generate_key(password, salt=None, count=None):
    if not salt:
        salt = get_random_bytes(16)
    if not count:
        count = random.randint(1, 20000)
    key = PBKDF2(password, salt, 32, count=count)
    hashed = base64.b64encode(salt).decode('utf-8') + base64.b64encode(str(count).encode('utf-8')).decode('utf-8')
    return hashed, key

def encrypt_with_pass(password, note):
    note = note.encode('utf-8')
    hashed, key = generate_key(password)
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted = cipher.encrypt(pad(note, AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    encrypted = base64.b64encode(encrypted).decode('utf-8')
    encrypted_note = iv + encrypted
    return encrypted_note, hashed

def decrypt_with_pass(password, encrypted_note, hashed):
    try:
        salt = base64.b64decode(hashed[:24])
        count = int(base64.b64decode(hashed[24:]).decode('utf-8'))
        _, key = generate_key(password, salt=salt, count=count)
        iv = base64.b64decode(encrypted_note[:24].encode('utf-8'))
        encrypted = base64.b64decode(encrypted_note[24:].encode('utf-8'))
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        return decrypted.decode('utf-8')
    except:
        return False





