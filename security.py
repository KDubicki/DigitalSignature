import os
import sys
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ANSI escape sequences for text colors
GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'

def generate_signature(file_name, person):
    if not os.path.exists(person):
        # Print the folder does not exist message in red
        print(RED + f'Error: Folder "{person}" does not exist.' + RESET)
        return

    if not os.path.exists(file_name):
        # Print the file does not exist message in red
        print(RED + f'Error: File "{file_name}" does not exist.' + RESET)
        return

    private_key_file = f'{person}/private_key.pem'
    signature_file = f'{person}_{file_name}.bin'

    # Check if the private key file exists
    if not os.path.exists(private_key_file):
        # Print the private key file does not exist message in red
        print(RED + f'Error: Private key file "{private_key_file}" does not exist.' + RESET)
        return

    try:
        # Load the private key
        with open(private_key_file, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        # Read the file content
        with open(file_name, 'rb') as f:
            file_content = f.read()

        # Calculate the hash of the file content
        file_hash = hashlib.sha256(file_content)

        # Sign the hash using the private key
        signature = private_key.sign(
            file_hash.digest(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Save the signature to a file
        with open(signature_file, 'wb') as f:
            f.write(signature)

        # Print the signature generation message in green
        print(GREEN + f'Signature generated for {file_name} by {person}:' + RESET)
        print(GREEN + f'Signature file: {signature_file}' + RESET)

    except Exception as e:
        # Print the exception message in red
        print(RED + f'Error: Failed to generate signature - {str(e)}' + RESET)


def verify_signature(signature_file, file_path, key_dict):
    if not os.path.exists(signature_file):
        # Print the signature file does not exist message in red
        print(RED + f'Error: Signature file "{signature_file}" does not exist.' + RESET)
        return

    if not os.path.exists(key_dict):
        # Print the key folder does not exist message in red
        print(RED + f'Error: Key folder "{key_dict}" does not exist.' + RESET)
        return

    if not os.path.exists(file_path):
        # Print the file does not exist message in red
        print(RED + f'Error: File "{file_path}" does not exist.' + RESET)
        return

    # Read the public key file
    public_key_file = f'{key_dict}/public_key.pem'
    if not os.path.exists(public_key_file):
        # Print the public key file does not exist message in red
        print(RED + f'Error: Public key file "{public_key_file}" does not exist.' + RESET)
        return

    try:
        # Read the public key from the key file
        with open(public_key_file, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )

        # Read the file content
        with open(file_path, 'rb') as f:
            file_content = f.read()

        # Compute the hash of the file content
        file_hash = hashlib.sha256(file_content).digest()

        # Read the signature from the file
        with open(signature_file, 'rb') as f:
            signature = f.read()

        try:
            # Verify the signature
            public_key.verify(
                signature,
                file_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print(GREEN + "Signature verification passed." + RESET)
        except:
            # Print the signature verification failed message in red
            print(RED + "Signature verification failed." + RESET)

    except Exception as e:
        # Print the exception message in red
        print(RED + f'Error: Failed to verify signature - {str(e)}' + RESET)


if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("Usage: python security.py generate <file_path> <person>")
        print("       python security.py verify <signature_file> <file_path> <person>")
        sys.exit(1)

    command = sys.argv[1]
    if command == 'generate':
        file_path = sys.argv[2]
        person = sys.argv[3]
        generate_signature(file_path, person)
    elif command == 'verify':
        signature_file = sys.argv[2]
        file_path = sys.argv[3]
        person = sys.argv[4]
        verify_signature(signature_file, file_path, person)
    else:
        print("Invalid command. Please use 'generate' or 'verify'.")