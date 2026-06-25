"""
GUI za slanje i prijem PGP poruka.

Upotreba u main.py:
    from gui_messages import MessagesFrame
    notebook.add(MessagesFrame(notebook), text="Poruke")
"""
from __future__ import annotations

import secrets
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from cryptography.exceptions import InvalidSignature

import key_ops
from exceptions import (
    PGPError,
    WrongPasswordError,
    KeyNotFoundError,
    KeyHasNoPrivatePartError,
)
from gui_keys import _PasswordDialog
from messaging.encode import PGPEncode, PGPDecode


def _format_key_label(entry: dict) -> str:
    return f"{entry['key_id']} — {entry['name']} <{entry['email']}>"


def _key_id_from_label(label: str) -> str | None:
    if not label:
        return None
    return label.split(" — ", 1)[0]


class MessagesFrame(ttk.Frame):
    """Encode/decode tab for the PGP application."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self._imported_path: str | None = None
        self._build_ui()
        self.refresh_keys()

    def _build_ui(self):
        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=8, pady=8)

        paned.add(self._build_encode_panel(), weight=1)
        paned.add(self._build_decode_panel(), weight=1)

    def _build_encode_panel(self) -> ttk.Frame:
        frame = ttk.LabelFrame(self, text="Slanje poruke")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        text_frame = ttk.Frame(frame)
        text_frame.grid(row=0, column=0, sticky="nsew", padx=8, pady=(8, 4))
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)

        self._plaintext = tk.Text(text_frame, wrap="word", height=12, width=40)
        scroll = ttk.Scrollbar(text_frame, orient="vertical", command=self._plaintext.yview)
        self._plaintext.configure(yscrollcommand=scroll.set)
        self._plaintext.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")

        options = ttk.LabelFrame(frame, text="Opcije kodiranja")
        options.grid(row=1, column=0, sticky="ew", padx=8, pady=4)

        self._auth_var = tk.BooleanVar(value=False)
        self._encrypt_var = tk.BooleanVar(value=False)
        self._compress_var = tk.BooleanVar(value=False)
        self._radix_var = tk.BooleanVar(value=False)

        ttk.Checkbutton(
            options, text="Autentifikacija (potpis)",
            variable=self._auth_var,
            command=self._update_encode_options,
        ).grid(row=0, column=0, sticky="w", padx=8, pady=2)
        ttk.Checkbutton(
            options, text="Enkripcija (tajnost)",
            variable=self._encrypt_var,
            command=self._update_encode_options,
        ).grid(row=1, column=0, sticky="w", padx=8, pady=2)
        ttk.Checkbutton(
            options, text="Kompresija (ZIP)",
            variable=self._compress_var,
        ).grid(row=2, column=0, sticky="w", padx=8, pady=2)
        ttk.Checkbutton(
            options, text="Radix64 konverzija",
            variable=self._radix_var,
        ).grid(row=3, column=0, sticky="w", padx=8, pady=2)

        keys = ttk.LabelFrame(frame, text="Ključevi")
        keys.grid(row=2, column=0, sticky="ew", padx=8, pady=4)
        keys.columnconfigure(1, weight=1)

        ttk.Label(keys, text="Potpis (privatni):").grid(row=0, column=0, sticky="w", padx=8, pady=4)
        self._signer_var = tk.StringVar()
        self._signer_combo = ttk.Combobox(
            keys, textvariable=self._signer_var, state="disabled", width=36,
        )
        self._signer_combo.grid(row=0, column=1, sticky="ew", padx=(0, 8), pady=4)

        ttk.Label(keys, text="Primalac (javni):").grid(row=1, column=0, sticky="w", padx=8, pady=4)
        self._recipient_var = tk.StringVar()
        self._recipient_combo = ttk.Combobox(
            keys, textvariable=self._recipient_var, state="disabled", width=36,
        )
        self._recipient_combo.grid(row=1, column=1, sticky="ew", padx=(0, 8), pady=4)

        ttk.Label(keys, text="Algoritam:").grid(row=2, column=0, sticky="w", padx=8, pady=4)
        algo_frame = ttk.Frame(keys)
        algo_frame.grid(row=2, column=1, sticky="w", padx=(0, 8), pady=4)
        self._algorithm_var = tk.StringVar(value="tripledes")
        self._algo_tripledes = ttk.Radiobutton(
            algo_frame, text="TripleDES", variable=self._algorithm_var, value="tripledes",
            state="disabled",
        )
        self._algo_aes = ttk.Radiobutton(
            algo_frame, text="AES-128", variable=self._algorithm_var, value="aes128",
            state="disabled",
        )
        self._algo_tripledes.pack(side="left")
        self._algo_aes.pack(side="left", padx=(12, 0))

        btn_bar = ttk.Frame(frame)
        btn_bar.grid(row=3, column=0, sticky="ew", padx=8, pady=(4, 8))
        ttk.Button(btn_bar, text="↻ Osveži ključeve",
                   command=self.refresh_keys).pack(side="left")
        ttk.Button(btn_bar, text="Kodiraj i sačuvaj…",
                   command=self._on_encode).pack(side="right")

        return frame

    def _build_decode_panel(self) -> ttk.Frame:
        frame = ttk.LabelFrame(self, text="Prijem poruke")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        text_frame = ttk.Frame(frame)
        text_frame.grid(row=0, column=0, sticky="nsew", padx=8, pady=(8, 4))
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)

        self._decoded_text = tk.Text(
            text_frame, wrap="word", height=12, width=40, state="disabled",
        )
        scroll = ttk.Scrollbar(text_frame, orient="vertical", command=self._decoded_text.yview)
        self._decoded_text.configure(yscrollcommand=scroll.set)
        self._decoded_text.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")

        self._set_decoded_text("Uvezite poruku i kliknite „Dekodiraj”.")

        btn_bar = ttk.Frame(frame)
        btn_bar.grid(row=1, column=0, sticky="ew", padx=8, pady=(4, 8))
        ttk.Button(btn_bar, text="Uvezi poruku…",
                   command=self._on_import).pack(side="left", padx=(0, 4))
        ttk.Button(btn_bar, text="Dekodiraj",
                   command=self._on_decode).pack(side="left")

        self._import_label = ttk.Label(
            frame, text="Nije uvezena nijedna datoteka.", foreground="gray",
        )
        self._import_label.grid(row=2, column=0, sticky="w", padx=8, pady=(0, 8))

        return frame

    def refresh_keys(self):
        private_labels = [_format_key_label(e) for e in key_ops.list_private_keys()]
        public_labels = [_format_key_label(e) for e in key_ops.list_keys()]

        self._signer_combo["values"] = private_labels
        self._recipient_combo["values"] = public_labels

        if self._signer_var.get() not in private_labels:
            self._signer_var.set(private_labels[0] if private_labels else "")
        if self._recipient_var.get() not in public_labels:
            self._recipient_var.set(public_labels[0] if public_labels else "")

        self._update_encode_options()

    def _update_encode_options(self):
        auth = self._auth_var.get()
        encrypt = self._encrypt_var.get()

        self._signer_combo.config(state="readonly" if auth and self._signer_combo["values"] else "disabled")
        self._recipient_combo.config(state="readonly" if encrypt and self._recipient_combo["values"] else "disabled")

        algo_state = "normal" if encrypt else "disabled"
        self._algo_tripledes.config(state=algo_state)
        self._algo_aes.config(state=algo_state)

    def _set_decoded_text(self, text: str):
        self._decoded_text.config(state="normal")
        self._decoded_text.delete("1.0", "end")
        self._decoded_text.insert("1.0", text)
        self._decoded_text.config(state="disabled")

    def _on_encode(self):
        plaintext = self._plaintext.get("1.0", "end-1c")
        if not plaintext.strip():
            messagebox.showerror("Greška", "Unesite tekst poruke.", parent=self)
            return

        auth = self._auth_var.get()
        encrypt = self._encrypt_var.get()
        compress = self._compress_var.get()
        radix = self._radix_var.get()

        if not any((auth, encrypt, compress, radix)):
            messagebox.showerror(
                "Greška",
                "Uključite bar jednu opciju kodiranja.",
                parent=self,
            )
            return

        signer_id = ""
        recipient_id = ""
        private_key = None
        public_key = None
        session_key = None
        algorithm = None
        signer_password = ""

        if auth:
            signer_id = _key_id_from_label(self._signer_var.get())
            if not signer_id:
                messagebox.showerror(
                    "Greška",
                    "Izaberite ključ za potpis ili generišite par u tabu „Upravljanje ključevima”.",
                    parent=self,
                )
                return
            dlg = _PasswordDialog(
                self,
                title="Lozinka potpisnika",
                prompt="Unesite lozinku privatnog ključa za potpis:",
            )
            if dlg.result is None:
                return
            signer_password = dlg.result

        if encrypt:
            recipient_id = _key_id_from_label(self._recipient_var.get())
            if not recipient_id:
                messagebox.showerror(
                    "Greška",
                    "Izaberite ključ primaoca ili uvezite javni ključ u prsten.",
                    parent=self,
                )
                return
            algorithm = self._algorithm_var.get()
            session_key = secrets.token_bytes(16)

        output_path = filedialog.asksaveasfilename(
            parent=self,
            title="Sačuvaj kodiranu poruku",
            defaultextension=".pgp",
            filetypes=[("PGP poruke", "*.pgp"), ("Svi fajlovi", "*.*")],
        )
        if not output_path:
            return

        try:
            if auth:
                private_key = key_ops.get_private_key(signer_id, signer_password)
            if encrypt:
                public_key = key_ops.get_public_key(recipient_id)

            PGPEncode(
                output_path,
                plaintext.encode("utf-8"),
                private_key,
                signer_id,
                session_key,
                recipient_id,
                public_key,
                algorithm,
                compress,
                radix,
            )
        except WrongPasswordError as e:
            messagebox.showerror("Pogrešna lozinka", str(e), parent=self)
            return
        except KeyNotFoundError as e:
            messagebox.showerror("Ključ nije pronađen", str(e), parent=self)
            return
        except KeyHasNoPrivatePartError as e:
            messagebox.showerror("Nema privatnog dela", str(e), parent=self)
            return
        except PGPError as e:
            messagebox.showerror("Greška pri kodiranju", str(e), parent=self)
            return
        except ValueError as e:
            messagebox.showerror("Greška pri kodiranju", str(e), parent=self)
            return

        messagebox.showinfo(
            "Uspeh",
            f"Poruka je sačuvana u:\n{output_path}",
            parent=self,
        )

    def _on_import(self):
        path = filedialog.askopenfilename(
            parent=self,
            title="Uvezi kodiranu poruku",
            filetypes=[("PGP poruke", "*.pgp"), ("Svi fajlovi", "*.*")],
        )
        if not path:
            return

        self._imported_path = path
        self._import_label.config(
            text=f"Uvezena datoteka: {path}",
            foreground="",
        )
        self._set_decoded_text("Datoteka je uvezena. Kliknite „Dekodiraj” za prikaz sadržaja.")

    def _on_decode(self):
        if not self._imported_path:
            messagebox.showerror(
                "Greška",
                "Prvo uvezite kodiranu poruku.",
                parent=self,
            )
            return

        dlg = _PasswordDialog(
            self,
            title="Lozinka za dekodiranje",
            prompt="Lozinka primaoca (prazno ako poruka nije enkriptovana):",
        )
        if dlg.result is None:
            return

        try:
            message = PGPDecode(self._imported_path, dlg.result)
            content = message.content.decode("utf-8", errors="replace")
            self._set_decoded_text(content)
        except WrongPasswordError as e:
            messagebox.showerror("Pogrešna lozinka", str(e), parent=self)
        except KeyNotFoundError as e:
            messagebox.showerror("Ključ nije pronađen", str(e), parent=self)
        except KeyHasNoPrivatePartError as e:
            messagebox.showerror("Nema privatnog dela", str(e), parent=self)
        except InvalidSignature:
            messagebox.showerror(
                "Nevažeći potpis",
                "Potpis poruke nije ispravan ili je sadržaj izmenjen.",
                parent=self,
            )
        except PGPError as e:
            messagebox.showerror("Greška pri dekodiranju", str(e), parent=self)
        except ValueError as e:
            messagebox.showerror("Greška pri dekodiranju", str(e), parent=self)
