from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES 
import os

key = os.urandom(16)
iv = os.urandom(16)

def encrypt(txt: str) -> str:
    c = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(txt.encode(), 16)
    ciphertext = c.encrypt(padded)
    return ciphertext.hex()

def decrypt(txt: str) -> (str, int):
    try:
        token = bytes.fromhex(txt)

        c = AES.new(key, AES.MODE_CBC, iv)  
        plaintext = c.decrypt(token)
        unpadded = unpad(plaintext, 16)
        
        return unpadded, 1
    except Exception as s:
        return str(s), 0

def main() -> None:
    while True:
        text = input("Please enter the ciphertext: ")
        text.strip()
        out, status = decrypt(text)
        print(out)
        if status == 1:
            print("Looks fine")
        else:
            print("Error...")

if __name__ == "__main__":
    print(encrypt("YELLOW SUBMARINE"))
    main()


