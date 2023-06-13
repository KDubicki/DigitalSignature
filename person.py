import os
import sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# ANSI escape sequence for green text
GREEN = '\033[92m'
RESET = '\033[0m'

def generate_keys(person_name):
    folder_name = person_name
    private_key_file = f'{folder_name}/private_key.pem'
    public_key_file = f'{folder_name}/public_key.pem'

    if os.path.exists(folder_name):
        print(f'Folder "{folder_name}" already exists. Skipping key generation.')
        return

    os.makedirs(folder_name, exist_ok=True)
    print(f'Created folder for {person_name}')

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Save the private key to a file
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_key_file, 'wb') as f:
        f.write(private_key_pem)

    # Save the public key to a file
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_key_file, 'wb') as f:
        f.write(public_key)

    # Print the generated keys in green
    print(GREEN + f'Generated keys for {person_name}:' + RESET)
    print(GREEN + f'Private key: {private_key_file}' + RESET)
    print(GREEN + f'Public key: {public_key_file}' + RESET)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        for person_name in sys.argv[1:]:
            generate_keys(person_name)
            
    else:
        person_name = input('Enter person name: ')
        generate_keys(person_name)