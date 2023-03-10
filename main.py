import base64
import binascii
import random
from Crypto.Cipher import AES


def encrypt(plaintext, secret_key, mode):
    if mode == AES.MODE_ECB:
        cipher = AES.new(secret_key, mode)
        iv = b''
    else:
        iv = bytes([random.randint(0, 255) for i in range(16)])
        cipher = AES.new(secret_key, mode, iv)

    pad = 16 - len(plaintext) % 16
    plaintext = plaintext + pad * chr(pad)

    encrypted = cipher.encrypt(plaintext.encode())

    if mode != AES.MODE_ECB:
        return base64.b64encode(iv + encrypted).decode()
    else:
        return base64.b64encode(encrypted).decode()


def decrypt(ciphertext, secret_key, mode):
    try:
        decoded = base64.b64decode(ciphertext.encode())
    except binascii.Error:
        print("Error: Could not decode ciphertext")
        return ""
    if mode == AES.MODE_ECB:
        cipher = AES.new(secret_key, mode)
    else:
        iv = decoded[:16]
        cipher = AES.new(secret_key, mode, iv)

    try:
        decrypted = cipher.decrypt(decoded[16:]) if mode != AES.MODE_ECB else cipher.decrypt(decoded)
        
        return decrypted[:-decrypted[-1]].decode()
    except UnicodeDecodeError:
        print("Error: Could not decode plaintext")
        return ""
    except ValueError:
        print("Error: Incorrect secret key")
        return ""


def main():
    plaintext = input("Enter plaintext: ")

    secret_key = input("Enter secret key: ").encode()

    mode = input("Select mode (ECB, CBC, CFB): ").upper()
    if mode == 'ECB':
        mode = AES.MODE_ECB
    elif mode == 'CBC':
        mode = AES.MODE_CBC
    elif mode == 'CFB':
        mode = AES.MODE_CFB
    else:
        print("Invalid mode")
        return

    encrypt_or_decrypt = input("Encrypt or decrypt (E/D): ").upper()

    if encrypt_or_decrypt == 'E':
        ciphertext = encrypt(plaintext, secret_key, mode)

        save = input("Save to file (Y/N): ").upper()
        if save == 'Y':
            file_name = input("Enter file name: ")
            file_path = './{}.txt'.format(file_name)

        with open(file_path, 'w') as f:
            f.write(ciphertext)

        print("Ciphertext:", ciphertext)

    else:
        read = input("Read from file (Y/N): ").upper()
        if read == 'Y':
            file_name = input("Enter file name: ")
            file_path = './{}.txt'.format(file_name)

            with open(file_path, 'r') as f:
                ciphertext = f.read()

        else:
            ciphertext = input("Enter ciphertext: ")

        plaintext = decrypt(ciphertext, secret_key, mode)
        print("Plaintext:", plaintext)


if __name__ == '__main__':
    main()
