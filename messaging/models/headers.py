import struct
from abc import ABC, abstractmethod


HEADER_TYPE_PLAIN = 0x00
HEADER_TYPE_AUTH = 0x01
HEADER_TYPE_ENCRYPTION = 0x02
HEADER_TYPE_COMPRESSION = 0x03
HEADER_TYPE_RADIX64 = 0x04


class Header(ABC):
    type: str

    @abstractmethod
    def to_dict(self) -> dict:
        pass

    @abstractmethod
    def to_bytes(self) -> bytes:
        pass

    @staticmethod
    def from_dict(data: dict):
        header_type = data.get("type")

        if header_type == "auth":
            return AuthHeader.from_dict(data)
        elif header_type == "encryption":
            return EncryptionHeader.from_dict(data)
        elif header_type == "compression":
            return CompressionHeader.from_dict(data)
        elif header_type == "radix64":
            return Radix64Header.from_dict(data)
        elif header_type == "plain":
            return PlainHeader.from_dict(data)
        else:
            raise ValueError(f"Unknown header type: {header_type}")

    @staticmethod
    def from_bytes(data: bytes):
        header_type = data[0]

        if header_type == HEADER_TYPE_AUTH:
            return AuthHeader.from_bytes(data)
        if header_type == HEADER_TYPE_ENCRYPTION:
            return EncryptionHeader.from_bytes(data)
        if header_type == HEADER_TYPE_COMPRESSION:
            return CompressionHeader.from_bytes(data)
        if header_type == HEADER_TYPE_RADIX64:
            return Radix64Header.from_bytes(data)
        if header_type == HEADER_TYPE_PLAIN:
            return PlainHeader.from_bytes(data)

        raise ValueError(f"Unknown header type byte: {header_type}")


def _read_length_prefixed(data: bytes, offset: int) -> tuple[bytes, int]:
    length = struct.unpack(">H", data[offset:offset + 2])[0]
    offset += 2
    value = data[offset:offset + length]
    return value, offset + length


class AuthHeader(Header):
    def __init__(self, signer: str, signature: bytes):
        self.type = "auth"
        self.signer = signer
        self.signature = signature

    def to_dict(self):
        return {
            "type": self.type,
            "signer": self.signer,
            "signature": self.signature
        }

    def to_bytes(self) -> bytes:
        signer = self.signer.encode("utf-8")
        return (
            bytes([HEADER_TYPE_AUTH])
            + struct.pack(">H", len(signer)) + signer
            + struct.pack(">H", len(self.signature)) + self.signature
        )

    @staticmethod
    def from_dict(data):
        return AuthHeader(
            signer=data["signer"],
            signature=data["signature"]
        )

    @staticmethod
    def from_bytes(data: bytes):
        offset = 1
        signer, offset = _read_length_prefixed(data, offset)
        signature, offset = _read_length_prefixed(data, offset)
        return AuthHeader(signer.decode("utf-8"), signature)


class EncryptionHeader(Header):
    def __init__(self, algorithm, encrypted_key, recipient_id):
        self.type = "encryption"
        self.algorithm = algorithm
        self.encrypted_key = encrypted_key
        self.recipient_id = recipient_id

    def to_dict(self):
        return {
            "type": self.type,
            "algorithm": self.algorithm,
            "encrypted_key": self.encrypted_key,
            "recipient_id": self.recipient_id
        }

    def to_bytes(self) -> bytes:
        algorithm = self.algorithm.encode("utf-8")
        recipient_id = self.recipient_id.encode("utf-8")
        return (
            bytes([HEADER_TYPE_ENCRYPTION])
            + struct.pack(">H", len(algorithm)) + algorithm
            + struct.pack(">H", len(self.encrypted_key)) + self.encrypted_key
            + struct.pack(">H", len(recipient_id)) + recipient_id
        )

    @staticmethod
    def from_dict(data):
        return EncryptionHeader(
            algorithm=data.get("algorithm"),
            encrypted_key=data.get("encrypted_key"),
            recipient_id=data.get("recipient_id")
        )

    @staticmethod
    def from_bytes(data: bytes):
        offset = 1
        algorithm, offset = _read_length_prefixed(data, offset)
        encrypted_key, offset = _read_length_prefixed(data, offset)
        recipient_id, offset = _read_length_prefixed(data, offset)
        return EncryptionHeader(
            algorithm.decode("utf-8"),
            encrypted_key,
            recipient_id.decode("utf-8")
        )


class CompressionHeader(Header):
    def __init__(self):
        self.type = "compression"

    def to_dict(self):
        return {
            "type": self.type
        }

    def to_bytes(self) -> bytes:
        return bytes([HEADER_TYPE_COMPRESSION])

    @staticmethod
    def from_dict(data):
        return CompressionHeader()

    @staticmethod
    def from_bytes(data: bytes):
        return CompressionHeader()


class Radix64Header(Header):
    def __init__(self):
        self.type = "radix64"

    def to_dict(self):
        return {"type": self.type}

    def to_bytes(self) -> bytes:
        return bytes([HEADER_TYPE_RADIX64])

    @staticmethod
    def from_dict(data):
        return Radix64Header()

    @staticmethod
    def from_bytes(data: bytes):
        return Radix64Header()


class PlainHeader(Header):
    def __init__(self):
        self.type = "plain"

    def to_dict(self):
        return {"type": self.type}

    def to_bytes(self) -> bytes:
        return bytes([HEADER_TYPE_PLAIN])

    @staticmethod
    def from_dict(data):
        return PlainHeader()

    @staticmethod
    def from_bytes(data: bytes):
        return PlainHeader()
