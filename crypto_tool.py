import argparse
from cryptography.fernet import Fernet

# Function to load the encryption key
def load_key():
    """
    Load the previously generated key from 'secret.key' file.
    """
    return open("secret.key", "rb").read()

# Function to encrypt a file
def encrypt_file(file_path, key):
    """
    Encrypts the specified file using the provided key.
    """
    fernet = Fernet(key)

    with open(file_path, "rb") as file:
        # Read the original file's data
        original_data = file.read()

    # Encrypt the data
    encrypted_data = fernet.encrypt(original_data)

    # Save the encrypted data back into the file (or a new file if preferred)
    with open(file_path + ".encrypted", "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

    print(f"File '{file_path}' has been encrypted and saved as '{file_path}.encrypted'.")

# Function to decrypt a file
def decrypt_file(file_path, key):
    """
    Decrypts the specified encrypted file using the provided key.
    """
    fernet = Fernet(key)

    with open(file_path, "rb") as encrypted_file:
        # Read the encrypted data
        encrypted_data = encrypted_file.read()

    # Decrypt the data
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception as e:
        print(f"Decryption failed: {e}")
        return

    # Save the decrypted data back into the file (or a new file if preferred)
    with open(file_path.replace(".encrypted", ".decrypted"), "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)

    print(f"File '{file_path}' has been decrypted and saved as '{file_path.replace('.encrypted', '.decrypted')}'.")

# Main function to handle the command-line arguments
def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files using a secret key.")
    
    # Add subcommands for encryption and decryption
    subparsers = parser.add_subparsers(dest="command", help="Choose to either encrypt or decrypt a file.")
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file.")
    encrypt_parser.add_argument("file", help="The path to the file to encrypt.")
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file.")
    decrypt_parser.add_argument("file", help="The path to the file to decrypt (must be a '.encrypted' file).")
    
    # Parse the command-line arguments
    args = parser.parse_args()

    # Load the encryption key from the key file
    try:
        key = load_key()
    except FileNotFoundError:
        print("Error: The key file 'secret.key' was not found. Please generate a key first using 'generate_key.py'.")
        return

    # Handle encryption
    if args.command == "encrypt":
        encrypt_file(args.file, key)

    # Handle decryption
    elif args.command == "decrypt":
        decrypt_file(args.file, key)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()