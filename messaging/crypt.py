import os
from abc import ABC


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Algorithm(ABC):

    def encrypt(self, message: bytes, key: bytes) -> bytes:
        pass

    def decrypt(self, message: bytes, key: bytes) -> bytes:
        pass


class TripleDES(Algorithm):
    def encrypt(self, message: bytes, key: bytes) -> bytes:
        iv = os.urandom(8)
        cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()
        return iv + ciphertext

    def decrypt(self, message: bytes, key: bytes) -> bytes:
        if len(message) < 8:
            raise ValueError("TripleDES ciphertext is too short")
        iv, ciphertext = message[:8], message[8:]
        cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


class AES128(Algorithm):
    def encrypt(self, message: bytes, key: bytes) -> bytes:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()
        return iv + ciphertext

    def decrypt(self, message: bytes, key: bytes) -> bytes:
        if len(message) < 16:
            raise ValueError("AES ciphertext is too short")
        iv, ciphertext = message[:16], message[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


def getAlgorithm(name):
    if name == "tripledes":
        return TripleDES()
    elif name == "aes128":
        return AES128()
    else:
        raise ValueError(f"Algorithm {name} not supported")
