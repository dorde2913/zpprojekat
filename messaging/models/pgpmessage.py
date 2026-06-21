import base64
import json
import struct
import zlib

import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from messaging.crypt import getAlgorithm
from messaging.models.headers import (
    AuthHeader,
    CompressionHeader,
    EncryptionHeader,
    Header,
    PlainHeader,
    Radix64Header,
)


class PGPMessage:
    def __init__(self, header: Header, content: bytes):
        self.header = header
        self.content = content

    def to_dict(self):
        return {
            "header": self.header.to_dict(),
            "content": self.content
        }

    def to_bytes(self) -> bytes:
        header_bytes = self.header.to_bytes()
        return (
            struct.pack(">I", len(header_bytes)) + header_bytes
            + struct.pack(">I", len(self.content)) + self.content
        )

    @staticmethod
    def from_bytes(data: bytes) -> "PGPMessage":
        offset = 0
        header_len = struct.unpack(">I", data[offset:offset + 4])[0]
        offset += 4
        header_bytes = data[offset:offset + header_len]
        offset += header_len
        content_len = struct.unpack(">I", data[offset:offset + 4])[0]
        offset += 4
        content = data[offset:offset + content_len]
        header = Header.from_bytes(header_bytes)
        return PGPMessage(header, content)

    def decodeContent(self, private_key=None, public_key=None):
        if isinstance(self.header, Radix64Header):
            return PGPMessage.from_bytes(base64.b64decode(self.content))

        if isinstance(self.header, CompressionHeader):
            return PGPMessage.from_bytes(zlib.decompress(self.content))

        if isinstance(self.header, EncryptionHeader):
            if private_key is None:
                raise ValueError("private_key required for decryption")
            session_key = private_key.decrypt(
                self.header.encrypted_key,
                padding.PKCS1v15()
            )
            algo = getAlgorithm(self.header.algorithm)
            decrypted = algo.decrypt(self.content, session_key)
            return PGPMessage.from_bytes(decrypted)

        if isinstance(self.header, AuthHeader):
            if public_key is None:
                raise ValueError("public_key required for auth verification")
            digest = hashlib.sha1(self.content).digest()
            public_key.verify(
                self.header.signature,
                digest,
                padding.PKCS1v15(),
                hashes.SHA1()
            )
            return PGPMessage(PlainHeader(), self.content)

        if isinstance(self.header, PlainHeader):
            return self

        raise ValueError(f"Unknown header type: {self.header.type}")

    @staticmethod
    def from_dict(data: dict):
        header = Header.from_dict(data["header"])
        return PGPMessage(header, data["content"])

    @staticmethod
    def from_json(data: str):
        return PGPMessage.from_dict(json.loads(data))

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def write_message(path: str, msg: PGPMessage):
    with open(path, "wb") as f:
        f.write(msg.to_bytes())


def read_message(path: str) -> PGPMessage:
    with open(path, "rb") as f:
        return PGPMessage.from_bytes(f.read())
