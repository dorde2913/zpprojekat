import itertools
import secrets
import unittest

import key_ops
from cryptography.exceptions import InvalidSignature
from exceptions import KeyHasNoPrivatePartError, KeyNotFoundError, WrongPasswordError
from messaging.encode import PGPEncode, PGPDecode
from messaging.models.headers import PlainHeader
from messaging.models.pgpmessage import PGPMessage, read_message, write_message
from tests.test_helpers import IsolatedKeyringTestCase, run_silently


class EndToEndKeyringTests(IsolatedKeyringTestCase):
    @classmethod
    def setUpClass(cls):
        cls.plaintext = b"Full end-to-end message through keyring"
        cls.algorithm = "aes128"

    def setUp(self):
        super().setUp()

        self.alice_password = "alice-secret"
        self.bob_password = "bob-secret"
        self.carol_password = "carol-secret"

        self.alice_id = self.generate_user("Alice", "alice@test.com", self.alice_password)
        self.bob_id = self.generate_user("Bob", "bob@test.com", self.bob_password)
        self.carol_id = self.generate_user("Carol", "carol@test.com", self.carol_password)

        self.alice_private = key_ops.get_private_key(self.alice_id, self.alice_password)
        self.bob_public = key_ops.get_public_key(self.bob_id)
        self.bob_private = key_ops.get_private_key(self.bob_id, self.bob_password)
        self.session_key = secrets.token_bytes(16)

    def _encode(
        self,
        *,
        auth=False,
        encrypt=False,
        compress=False,
        radix=False,
        signer_id="",
        recipient_id="",
        private_key=None,
        public_key=None,
        output_name="message.bin",
    ):
        output_file = self.message_path(output_name)
        algorithm = self.algorithm if encrypt else None
        session_key = self.session_key if encrypt else None

        return run_silently(
            PGPEncode,
            output_file,
            self.plaintext,
            private_key,
            signer_id,
            session_key,
            recipient_id,
            public_key,
            algorithm,
            compress,
            radix,
        )

    def _decode(self, output_name="message.bin", password=""):
        return run_silently(
            PGPDecode,
            self.message_path(output_name),
            password,
        )

    def test_keygen_and_lookup_used_for_sign_and_encrypt(self):
        self._encode(
            auth=True,
            encrypt=True,
            compress=True,
            radix=True,
            signer_id=self.alice_id,
            recipient_id=self.bob_id,
            private_key=self.alice_private,
            public_key=self.bob_public,
        )

        decoded = self._decode(password=self.bob_password)

        self.assertIsInstance(decoded.header, PlainHeader)
        self.assertEqual(decoded.content, self.plaintext)

    def test_auth_only_resolves_signer_public_key_from_keyring(self):
        self._encode(
            auth=True,
            signer_id=self.alice_id,
            private_key=self.alice_private,
        )

        decoded = self._decode(password="unused-for-auth-only")

        self.assertEqual(decoded.content, self.plaintext)

    def test_encrypt_only_resolves_recipient_private_key_with_password(self):
        self._encode(
            encrypt=True,
            recipient_id=self.bob_id,
            public_key=self.bob_public,
        )

        decoded = self._decode(password=self.bob_password)

        self.assertEqual(decoded.content, self.plaintext)

    def test_wrong_password_on_encrypted_message(self):
        self._encode(
            encrypt=True,
            recipient_id=self.bob_id,
            public_key=self.bob_public,
        )

        with self.assertRaises(WrongPasswordError) as ctx:
            self._decode(password="not-bob-password")

        self.assertEqual(ctx.exception.key_id, self.bob_id)

    def test_missing_signer_in_keyring(self):
        self._encode(
            auth=True,
            signer_id=self.alice_id,
            private_key=self.alice_private,
            output_name="signed-by-alice.bin",
        )

        key_ops.delete_key(self.alice_id)

        with self.assertRaises(KeyNotFoundError) as ctx:
            self._decode(output_name="signed-by-alice.bin", password="")

        self.assertEqual(ctx.exception.key_id, self.alice_id)

    def test_missing_recipient_private_key_in_keyring(self):
        carol_public = key_ops.get_public_key(self.carol_id)

        self._encode(
            encrypt=True,
            recipient_id=self.carol_id,
            public_key=carol_public,
            output_name="for-carol.bin",
        )

        key_ops.delete_key(self.carol_id)

        with self.assertRaises(KeyNotFoundError) as ctx:
            self._decode(output_name="for-carol.bin", password=self.carol_password)

        self.assertEqual(ctx.exception.key_id, self.carol_id)

    def test_recipient_public_only_cannot_decrypt(self):
        self._encode(
            encrypt=True,
            recipient_id=self.bob_id,
            public_key=self.bob_public,
            output_name="bob-encrypted.bin",
        )

        bob_pub_pem = self._export_public_pem(self.bob_id)
        key_ops.delete_key(self.bob_id)
        key_ops.import_public_key(
            bob_pub_pem,
            "Bob Public",
            "bob-public@test.com",
        )

        with self.assertRaises(KeyHasNoPrivatePartError) as ctx:
            self._decode(output_name="bob-encrypted.bin", password=self.bob_password)

        self.assertEqual(ctx.exception.key_id, self.bob_id)

    def test_wrong_recipient_password_even_when_signer_key_exists(self):
        self._encode(
            auth=True,
            encrypt=True,
            signer_id=self.alice_id,
            recipient_id=self.bob_id,
            private_key=self.alice_private,
            public_key=self.bob_public,
            output_name="alice-to-bob.bin",
        )

        with self.assertRaises(WrongPasswordError) as ctx:
            self._decode(output_name="alice-to-bob.bin", password=self.alice_password)

        self.assertEqual(ctx.exception.key_id, self.bob_id)

    def test_tampered_signature_fails_verification(self):
        self._encode(
            auth=True,
            signer_id=self.alice_id,
            private_key=self.alice_private,
            output_name="tampered.bin",
        )

        path = self.message_path("tampered.bin")
        message = read_message(path)
        tampered_content = message.content[:-1] + bytes([message.content[-1] ^ 0xFF])
        write_message(path, PGPMessage(message.header, tampered_content))

        with self.assertRaises(InvalidSignature):
            self._decode(output_name="tampered.bin", password="")

    def test_all_option_combinations_through_keyring(self):
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
                output_name = f"combo-{int(auth)}{int(encrypt)}{int(compress)}{int(radix)}.bin"

                self._encode(
                    auth=auth,
                    encrypt=encrypt,
                    compress=compress,
                    radix=radix,
                    signer_id=self.alice_id if auth else "",
                    recipient_id=self.bob_id if encrypt else "",
                    private_key=self.alice_private if auth else None,
                    public_key=self.bob_public if encrypt else None,
                    output_name=output_name,
                )

                password = self.bob_password if encrypt else ""
                decoded = self._decode(output_name=output_name, password=password)

                self.assertIsInstance(decoded.header, PlainHeader)
                self.assertEqual(decoded.content, self.plaintext)

    def _export_public_pem(self, key_id: str) -> str:
        path = self.message_path(f"{key_id}-public.pem")
        key_ops.export_public_key(key_id, path)
        return path


if __name__ == "__main__":
    unittest.main()
