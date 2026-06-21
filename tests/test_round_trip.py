import io
import itertools
import os
import secrets
import tempfile
import unittest
from contextlib import redirect_stdout

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from messaging.encode import PGPEncode, PGPDecode
from messaging.models.headers import (
    AuthHeader,
    CompressionHeader,
    EncryptionHeader,
    PlainHeader,
    Radix64Header,
)


def expected_outer_header_type(auth, encrypt, compress, radix):
    if radix:
        return Radix64Header
    if compress:
        return CompressionHeader
    if encrypt:
        return EncryptionHeader
    if auth:
        return AuthHeader
    return PlainHeader


class RoundTripCombinationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        cls.public_key = cls.private_key.public_key()
        cls.session_key = secrets.token_bytes(16)
        cls.plaintext = b"Hello this is a round-trip test message"
        cls.signer_id = "test-signer"
        cls.recipient_id = "test-recipient"
        cls.algorithm = "tripledes"

    def setUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self._previous_cwd = os.getcwd()
        os.chdir(self._temp_dir.name)

    def tearDown(self):
        os.chdir(self._previous_cwd)
        self._temp_dir.cleanup()

    def _encode_decode(self, auth, encrypt, compress, radix):
        encode_private_key = self.private_key if auth else None
        session_key = self.session_key if encrypt else None
        public_key = self.public_key if encrypt else None
        algorithm = self.algorithm if encrypt else None

        with redirect_stdout(io.StringIO()):
            encoded = PGPEncode(
                self.plaintext,
                encode_private_key,
                self.signer_id,
                session_key,
                self.recipient_id,
                public_key,
                algorithm,
                compress,
                radix,
            )
            decoded = PGPDecode(
                "testfile.txt",
                private_key=self.private_key,
                public_key=self.public_key,
            )

        return encoded, decoded

    def test_round_trip_all_option_combinations(self):
        for auth, encrypt, compress, radix in itertools.product(
            (False, True),
            repeat=4,
        ):
            with self.subTest(
                auth=auth,
                encrypt=encrypt,
                compress=compress,
                radix=radix,
            ):
                encoded, decoded = self._encode_decode(
                    auth,
                    encrypt,
                    compress,
                    radix,
                )

                expected_header = expected_outer_header_type(
                    auth,
                    encrypt,
                    compress,
                    radix,
                )
                self.assertIsInstance(encoded.header, expected_header)
                self.assertIsInstance(decoded.header, PlainHeader)
                self.assertEqual(decoded.content, self.plaintext)

    def test_round_trip_none_enabled(self):
        encoded, decoded = self._encode_decode(False, False, False, False)
        self.assertIsInstance(encoded.header, PlainHeader)
        self.assertEqual(decoded.content, self.plaintext)

    def test_round_trip_auth_only(self):
        encoded, decoded = self._encode_decode(True, False, False, False)
        self.assertIsInstance(encoded.header, AuthHeader)
        self.assertEqual(decoded.content, self.plaintext)

    def test_round_trip_encryption_only(self):
        encoded, decoded = self._encode_decode(False, True, False, False)
        self.assertIsInstance(encoded.header, EncryptionHeader)
        self.assertEqual(decoded.content, self.plaintext)

    def test_round_trip_compression_only(self):
        encoded, decoded = self._encode_decode(False, False, True, False)
        self.assertIsInstance(encoded.header, CompressionHeader)
        self.assertEqual(decoded.content, self.plaintext)

    def test_round_trip_radix_only(self):
        encoded, decoded = self._encode_decode(False, False, False, True)
        self.assertIsInstance(encoded.header, Radix64Header)
        self.assertEqual(decoded.content, self.plaintext)

    def test_round_trip_all_enabled(self):
        encoded, decoded = self._encode_decode(True, True, True, True)
        self.assertIsInstance(encoded.header, Radix64Header)
        self.assertEqual(decoded.content, self.plaintext)


if __name__ == "__main__":
    unittest.main()
