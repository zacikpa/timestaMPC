import os
import sys
import json

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_private_key(filename: str, size: int):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=size,
    )

    with open(filename, "wb") as f:
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        f.write(pem)
        
    public_key = private_key.public_key()
    with open(f'{filename}.pub', "wb") as f:
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1,
        )
        f.write(pem)
        
    return public_key

def generate_keys(num_parties):
    
    os.makedirs('keys/', exist_ok=True)
    for party in range(num_parties):
        generate_private_key(f'keys/signer-key-{party}', 4096)
    generate_private_key(f'keys/manager-key', 4096)
        
        

def main():
    if len(sys.argv) != 2:
        print("Usage:", sys.argv[0], "CONFIG_FILE")
    config_filename = sys.argv[1]
    with open(config_filename, "r") as config_file:
        config = json.load(config_file)
        
    num_parties = config["num_parties"]
    generate_keys(num_parties)
        
if __name__ == '__main__':
    main()