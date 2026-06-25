import itertools
import secrets
import unittest

import key_ops
from messaging.encode import PGPEncode, PGPDecode
from messaging.models.headers import (
    AuthHeader,
    CompressionHeader,
    EncryptionHeader,
    PlainHeader,
    Radix64Header,
)
from tests.test_helpers import IsolatedKeyringTestCase, run_silently


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


class RoundTripCombinationTests(IsolatedKeyringTestCase):
    @classmethod
    def setUpClass(cls):
        cls.plaintext = b"Hello this is a round-trip test message"
        cls.algorithm = "tripledes"
        cls.password = "round-trip-pass"

    def setUp(self):
        super().setUp()
        self.key_id = self.generate_user("Round Trip", "roundtrip@test.com", self.password)
        self.private_key = key_ops.get_private_key(self.key_id, self.password)
        self.public_key = key_ops.get_public_key(self.key_id)
        self.session_key = secrets.token_bytes(16)

    def _encode_decode(self, auth, encrypt, compress, radix):
        output_file = self.message_path("encoded.bin")

        encode_private_key = self.private_key if auth else None
        signer_id = self.key_id if auth else ""
        session_key = self.session_key if encrypt else None
        recipient_id = self.key_id if encrypt else ""
        public_key = self.public_key if encrypt else None
        algorithm = self.algorithm if encrypt else None

        encoded = run_silently(
            PGPEncode,
            output_file,
            self.plaintext,
            encode_private_key,
            signer_id,
            session_key,
            recipient_id,
            public_key,
            algorithm,
            compress,
            radix,
        )
        decoded = run_silently(
            PGPDecode,
            output_file,
            self.password,
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
