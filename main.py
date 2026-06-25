# import secrets

# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.asymmetric import rsa

# from messaging.encode import PGPEncode, PGPDecode


# #temp dok nemamo key management
# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048,
#     backend=default_backend()
# )

# public_key = private_key.public_key()

# session_key = secrets.token_bytes(16)  # 16 bytes = 128 bits

# print(PGPEncode(
#     b"Hello this is a message",
#     None,
#     "signer",
#     session_key,
#     "boban",
#     public_key,
#     "tripledes",
#     False,
#     True
# ).to_dict())

# PGPDecode("testfile.txt",private_key,public_key)
"""
PGP aplikacija — pokretanje.

Svi moduli moraju biti u istom folderu:
    keyring.py, exceptions.py, key_ops.py, gui_keys.py
"""

import tkinter as tk
from tkinter import ttk
from gui_keys import KeyRingFrame
from gui_messages import MessagesFrame


def main():
    root = tk.Tk()
    root.title("PGP Aplikacija")
    root.geometry("960x560")
    root.minsize(820, 480)

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=8, pady=8)

    keys_frame = KeyRingFrame(notebook)
    notebook.add(keys_frame, text="  Upravljanje ključevima  ")

    msg_frame = MessagesFrame(notebook)
    notebook.add(msg_frame, text="  Poruke  ")

    root.mainloop()


if __name__ == "__main__":
    main()

