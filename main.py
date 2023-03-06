import base64
from Crypto.Cipher import AES


def encrypt(plaintext, secret_key, mode):
    pad = 16 - len(plaintext) % 16
    plaintext = plaintext + pad * chr(pad)

    cipher = AES.new(secret_key, mode)

    encrypted = cipher.encrypt(plaintext.encode())
    return base64.b64encode(encrypted).decode()


def decrypt(ciphertext, secret_key, mode):
    decoded = base64.b64decode(ciphertext.encode())
    cipher = AES.new(secret_key, mode)
    
    decrypted = cipher.decrypt(decoded)
    return decrypted.rstrip(bytes([decrypted[-1]])).decode()

def main():
    plaintext = input("Enter plaintext: ")

    # Secret key must be 16, 24, or 32 bytes long
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
            file_path = input("Enter file path: ")

            with open(file_path, 'w') as f:
                f.write(ciphertext)

        print("Ciphertext:", ciphertext)

    else:
        read = input("Read from file (Y/N): ").upper()
        if read == 'Y':
            file_path = input("Enter file path: ")

            with open(file_path, 'r') as f:ciphertext = f.read()
        else:
            ciphertext = input("Enter ciphertext: ")

        plaintext = decrypt(ciphertext, secret_key, mode)
    print("Plaintext:", plaintext)


if __name__ == '__main__':
    main()
