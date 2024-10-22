# generate_key.py
from cryptography.fernet import Fernet

def generate_key():
    # Generate a key for encryption
    key = Fernet.generate_key()
    print(f"Key: {key}")
    
    # Save the key into a file
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

if __name__ == "__main__":
    generate_key()
    print("Key generated and saved as 'secret.key'")

    ##spara den genererade nyckeln till en text fil, denna textfil är den som ska krypteras och dekrypteras. Låt användaren själv skriva in
    ##vilket meddelande den vill kryptera