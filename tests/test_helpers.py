"""Shared helpers for messaging and keyring tests."""

import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

import key_ops
from keyring import KeyRing


class IsolatedKeyringTestCase(unittest.TestCase):
    """Each test gets a fresh KeyRing backed by a temporary directory."""

    def setUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self._messages_dir = os.path.join(self._temp_dir.name, "messages")
        os.makedirs(self._messages_dir, exist_ok=True)

        self._previous_kr = key_ops._kr
        key_ops._kr = KeyRing(os.path.join(self._temp_dir.name, "keyring"))

    def tearDown(self):
        key_ops._kr = self._previous_kr
        self._temp_dir.cleanup()

    def message_path(self, name: str = "message.bin") -> str:
        return os.path.join(self._messages_dir, name)

    @staticmethod
    def generate_user(name: str, email: str, password: str) -> str:
        return key_ops.generate_key(name, email, 2048, password)


def run_silently(fn, *args, **kwargs):
    with redirect_stdout(io.StringIO()):
        return fn(*args, **kwargs)
