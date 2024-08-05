# Library & Modules
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization 

# AES(Advance Encryption Standard) encryption
def aes_encryption(message, key):
    cipher_suite = Fernet(key)
    cipher_text = cipher_suite.encrypt(message)
    return cipher_text

# RSA() encryption
def rsa_encryption(message, public_key):
    public_key = serialization.load_pem_public_key(public_key)
    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

# Generate a key for AES
key = Fernet.generate_key()

# Generate a key pair for RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()
pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Test message
message = b"A really secret message, maybe a pincode"

# AES Encryption
encrypted_message = aes_encryption(message, key)
print("AES Encrypted message: ", encrypted_message)

# RSA Encryption
encrypted_message = rsa_encryption(message, pem)
print("RSA Encrypted message: ", encrypted_message)

