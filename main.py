import Crypto.Random as pycrypto
from Crypto.Cipher import AES
import os
import sys
from tqdm import tqdm  # Add tqdm for progress bar

print("VAULT")

def search_external_drives_for_key():
    print("Searching external drives for keys.txt")
    drives = [f"{chr(letter)}:\\" for letter in range(65, 91) if os.path.exists(f"{chr(letter)}:\\")]
    for drive in drives:
        if os.path.exists(os.path.join(drive, "keys.txt")):
            print(f"Found keys.txt in {drive}")
            return os.path.join(drive, "keys.txt")
    print("keys.txt not found on any external drives")
    return None

def generate_key(existing_key_path=None):
    print("Generating a new 256-bit key")
    if existing_key_path:
        try:
            key = pycrypto.get_random_bytes(32)  # 256-bit key
            with open(existing_key_path, "wb") as key_file:
                key_file.write(key)
            print(f"New key regenerated and saved to {existing_key_path}")
            return key
        except PermissionError:
            print(f"Permission denied: Unable to write to {existing_key_path}.")
        except Exception as e:
            print(f"Unexpected error while writing to {existing_key_path}: {e}")

    drives = [f"{chr(letter)}:\\" for letter in range(65, 91) if os.path.exists(f"{chr(letter)}:\\")]
    for drive in drives:
        key_path = os.path.join(drive, "keys.txt")
        if not os.path.exists(key_path):  # Only attempt to write if keys.txt does not exist
            try:
                key = pycrypto.get_random_bytes(32)  # 256-bit key
                with open(key_path, "wb") as key_file:
                    key_file.write(key)
                print(f"New key generated and saved to {key_path}")
                return key
            except PermissionError:
                print(f"Permission denied: Unable to write to {key_path}. Trying another drive.")
            except Exception as e:
                print(f"Unexpected error while writing to {key_path}: {e}")
    print("No available external drive to create keys.txt. Please insert a drive.")
    return None

def load_key():
    key_path = search_external_drives_for_key()
    if key_path:
        try:
            with open(key_path, "rb") as key_file:
                key = key_file.read()
                if len(key) == 32:  # Ensure the key is 256 bits (32 bytes)
                    print(f"Key successfully loaded from {key_path}")
                    return key
                else:
                    print(f"Invalid key found in {key_path}. Regenerating key.")
                    return generate_key(existing_key_path=key_path)
        except PermissionError:
            print(f"Permission denied: Unable to read from {key_path}.")
        except Exception as e:
            print(f"Unexpected error while reading from {key_path}: {e}")
    print("Attempting to generate a new key.")
    return generate_key()

def encrypt_file(key, file_path):
    print(f"Encrypting {file_path}")
    with open(file_path, "rb") as f:
        data = f.read()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    with open(file_path, "wb") as f:
        f.write(cipher.nonce + tag + ciphertext)

def decrypt_file(key, file_path):
    print(f"Decrypting {file_path}")
    with open(file_path, "rb") as f:
        nonce, tag, ciphertext = f.read(16), f.read(16), f.read()
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    with open(file_path, "wb") as f:
        f.write(data)

def encrypt_vault(key):
    print("Encrypting files in the vault")
    for root, _, files in os.walk("vault"):  # Recursively walk through all subdirectories
        for file in tqdm(files, desc=f"Encrypting files in {root}", unit="file"):
            file_path = os.path.join(root, file)
            encrypt_file(key, file_path)

def decrypt_vault(key):
    print("Decrypting files in the vault")
    for root, _, files in os.walk("vault"):  # Recursively walk through all subdirectories
        for file in tqdm(files, desc=f"Decrypting files in {root}", unit="file"):
            file_path = os.path.join(root, file)
            decrypt_file(key, file_path)

def main():
    print("Starting Vault")
    key_path = search_external_drives_for_key()
    key = load_key()
    if not key:
        print("Failed to load or generate a key. Exiting.")
        sys.exit()
    print("Vault is ready")
    print("What would you like to do?")
    print("1. Encrypt")
    print("2. Decrypt")
    print("3. New key")
    print("4. Exit")
    choice = input("Choice: ")
    if choice == "1":
        encrypt_vault(key)
    elif choice == "2":
        decrypt_vault(key)
    elif choice == "3":
        if key_path:
            generate_key(existing_key_path=key_path)
        else:
            print("No existing key path found. Attempting to generate a new key.")
            generate_key()
    elif choice == "4":
        sys.exit()
    else:
        print("Invalid choice")
        main()

if __name__ == "__main__":
    main()



