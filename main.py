import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from messaging.encode import PGPEncode, PGPDecode


#temp dok nemamo key management
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_key = private_key.public_key()

session_key = secrets.token_bytes(16)  # 16 bytes = 128 bits

print(PGPEncode(
    b"Hello this is a message",
    None,
    "signer",
    session_key,
    "boban",
    public_key,
    "tripledes",
    False,
    True
).to_dict())

PGPDecode("testfile.txt",private_key,public_key)


