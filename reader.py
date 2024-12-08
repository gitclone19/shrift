import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def is_base64(data):
    """Base64 ekanligini tekshiradi."""
    try:
        base64.b64decode(data)
        return True
    except Exception:
        return False

def base64_decode(data):
    """Base64 shifrdan chiqarish."""
    return base64.b64decode(data).decode('utf-8')

def is_hex(data):
    """Hex ekanligini tekshiradi."""
    try:
        bytes.fromhex(data)
        return True
    except ValueError:
        return False

def hex_decode(data):
    """Hex shifrdan chiqarish."""
    return bytes.fromhex(data).decode('utf-8')

def aes_decrypt(data, key):
    """AES shifrdan chiqarish."""
    try:
        raw_data = base64.b64decode(data)
        iv = raw_data[:AES.block_size]
        encrypted_data = raw_data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return decrypted_data.decode('utf-8')
    except Exception:
        return None

def caesar_decrypt(data, shift):
    """Caesar Cipher shifrdan chiqarish."""
    decrypted = ''.join(
        chr((ord(char) - shift - 65) % 26 + 65) if char.isupper() else
        chr((ord(char) - shift - 97) % 26 + 97) if char.islower() else char
        for char in data
    )
    return decrypted

def detect_and_decrypt(data):
    """Shifrlash turini aniqlash va shifrdan chiqarish."""
    if is_base64(data):
        print("Base64 shifrlash aniqlandi.")
        return base64_decode(data)

    if is_hex(data):
        print("Hex shifrlash aniqlandi.")
        return hex_decode(data)

    # AES shifrlash uchun kalit so'rash
    aes_key = input("AES kalitini kiriting (yoki bo'sh qoldiring): ")
    if aes_key:
        key = hashlib.sha256(aes_key.encode()).digest()
        aes_result = aes_decrypt(data, key)
        if aes_result:
            print("AES shifrlash aniqlandi.")
            return aes_result

    # Caesar Cipher uchun avtomatik sinov (0-25 oralig'ida)
    print("Caesar Cipher sinovi boshlanmoqda...")
    for shift in range(1, 26):
        decrypted = caesar_decrypt(data, shift)
        if decrypted.isprintable():
            print(f"Caesar Cipher aniqlandi (Shift: {shift}).")
            return decrypted

    return "Shifrlash turini aniqlab bo'lmadi yoki noto'g'ri kalit kiritildi."

def main():
    print("Shifrdan chiqaruvchi dastur")
    data = input("Shifrlangan matnni kiriting: ")
    result = detect_and_decrypt(data)
    print(f"Natija: {result}")

if __name__ == "__main__":
    main()
