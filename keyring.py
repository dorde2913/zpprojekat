"""
PGP Key Ring

Key ID = poslednjih 8 hex cifara SHA-1 fingerprinta javnog ključa.
"""

import json
import os
import hashlib
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

DEFAULT_KEYRING_DIR = os.path.join(os.path.expanduser("~"), "pgp_keyring")

def _compute_key_id(public_key) -> str:
    """
    Vraća 8-cifreni hex Key ID = poslednjih 32 bita SHA-1 fingerprinta.
    Fingerprint se računa nad DER-enkodovanim javnim ključem.
    """
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    sha1 = hashlib.sha1(der).hexdigest()
    return sha1[-8:].upper()


def _compute_fingerprint(public_key) -> str:
    """Pun 40-cifreni SHA-1 fingerprint javnog ključa."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha1(der).hexdigest().upper()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

class KeyRing:
    """
    Upravlja prstenom javnih i privatnih ključeva.

    Svaki unos u keyring.json izgleda ovako:
    {
        "key_id":      "A3F2C1B0",
        "fingerprint": "...40 hex cifara...",
        "name":        "Marko Markovic",
        "email":       "marko@example.com",
        "key_size":    2048,
        "created_at":  "2025-06-01T12:00:00Z",
        "has_private": true
    }
    """

    def __init__(self, keyring_dir: str = DEFAULT_KEYRING_DIR):
        self.keyring_dir = keyring_dir
        self._priv_dir = os.path.join(keyring_dir, "private")
        self._pub_dir  = os.path.join(keyring_dir, "public")
        self._meta_path = os.path.join(keyring_dir, "keyring.json")
        self._ensure_dirs()
        self._metadata: list[dict] = self._load_metadata()

    def _ensure_dirs(self):
        os.makedirs(self._priv_dir, exist_ok=True)
        os.makedirs(self._pub_dir,  exist_ok=True)

    def _load_metadata(self) -> list[dict]:
        if not os.path.exists(self._meta_path):
            return []
        with open(self._meta_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_metadata(self):
        with open(self._meta_path, "w", encoding="utf-8") as f:
            json.dump(self._metadata, f, indent=2, ensure_ascii=False)

    def generate_key_pair(
        self,
        name: str,
        email: str,
        key_size: int,
        password: str,
    ) -> str:
        """
        Generiše novi RSA par ključeva.
        Čuva privatni ključ enkriptovan lozinkom, javni ključ čist.
        Vraća Key ID novog para.

        Parametri:
            name      - ime korisnika
            email     - e-mail adresa
            key_size  - 1024 ili 2048
            password  - lozinka za enkripciju privatnog ključa

        Greška:
            ValueError ako key_size nije 1024 ili 2048.
        """
        if key_size not in (1024, 2048):
            raise ValueError("Veličina ključa mora biti 1024 ili 2048 bita.")

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        public_key = private_key.public_key()

        key_id = _compute_key_id(public_key)
        # Ako postoji kolizija (ekstremno retko), dodaj sufiks
        if any(e["key_id"] == key_id for e in self._metadata):
            key_id = key_id + "X"

        self._write_private_pem(key_id, private_key, password)
        self._write_public_pem(key_id, public_key)

        entry = {
            "key_id":      key_id,
            "fingerprint": _compute_fingerprint(public_key),
            "name":        name,
            "email":       email,
            "key_size":    key_size,
            "created_at":  _now_iso(),
            "has_private": True,
        }
        self._metadata.append(entry)
        self._save_metadata()
        return key_id

    def delete_key(self, key_id: str):
        """
        Briše ključ (ili par) sa datim Key ID-jem.
        Greška ako key_id ne postoji.
        """
        entry = self._find_entry(key_id)  # baca KeyError ako nema

        priv_path = os.path.join(self._priv_dir, f"{key_id}.pem")
        pub_path  = os.path.join(self._pub_dir,  f"{key_id}.pem")

        if os.path.exists(priv_path):
            os.remove(priv_path)
        if os.path.exists(pub_path):
            os.remove(pub_path)

        self._metadata = [e for e in self._metadata if e["key_id"] != key_id]
        self._save_metadata()

    # ── uvoz ──────────────────────────────────────────────────────────────────

    def import_public_key(self, pem_path: str, name: str, email: str) -> str:
        """
        Uvozi javni ključ iz .pem fajla.
        name i email su obavezni jer PEM fajl ih ne sadrži.
        Vraća Key ID.
        """
        with open(pem_path, "rb") as f:
            pem_data = f.read()

        public_key = serialization.load_pem_public_key(
            pem_data, backend=default_backend()
        )

        key_id = _compute_key_id(public_key)
        if any(e["key_id"] == key_id for e in self._metadata):
            raise ValueError(f"Ključ sa ID-jem {key_id} već postoji u prstenu.")

        key_size = public_key.key_size
        self._write_public_pem(key_id, public_key)

        entry = {
            "key_id":      key_id,
            "fingerprint": _compute_fingerprint(public_key),
            "name":        name,
            "email":       email,
            "key_size":    key_size,
            "created_at":  _now_iso(),
            "has_private": False,
        }
        self._metadata.append(entry)
        self._save_metadata()
        return key_id

    def import_key_pair(self, pem_path: str, password: str, new_password: str) -> str:
        """
        Uvozi par ključeva iz enkriptovanog PEM fajla.
        password     - lozinka kojom je ulazni PEM enkriptovan
        new_password - lozinka pod kojom će biti sačuvan lokalno
        Vraća Key ID.
        """
        with open(pem_path, "rb") as f:
            pem_data = f.read()

        private_key = serialization.load_pem_private_key(
            pem_data,
            password=password.encode("utf-8"),
            backend=default_backend(),
        )
        public_key = private_key.public_key()

        key_id = _compute_key_id(public_key)
        if any(e["key_id"] == key_id for e in self._metadata):
            raise ValueError(f"Ključ sa ID-jem {key_id} već postoji u prstenu.")

        key_size = private_key.key_size
        self._write_private_pem(key_id, private_key, new_password)
        self._write_public_pem(key_id, public_key)

        # Pokušaj da izvučemo name/email iz komentara ako postoji — inače placeholder
        entry = {
            "key_id":      key_id,
            "fingerprint": _compute_fingerprint(public_key),
            "name":        "(uvezeno)",
            "email":       "(uvezeno)",
            "key_size":    key_size,
            "created_at":  _now_iso(),
            "has_private": True,
        }
        self._metadata.append(entry)
        self._save_metadata()
        return key_id


    def export_public_key(self, key_id: str, dest_path: str):
        """Izvozi javni ključ u PEM fajl."""
        self._find_entry(key_id)
        pub_path = os.path.join(self._pub_dir, f"{key_id}.pem")
        with open(pub_path, "rb") as src, open(dest_path, "wb") as dst:
            dst.write(src.read())

    def export_key_pair(self, key_id: str, password: str, dest_path: str):
        """
        Izvozi ceo par u enkriptovani PEM fajl.
        Proverava lozinku pre izvoza (baca ValueError ako je netačna).
        """
        # get_private_key proverava lozinku i baca grešku ako ne valja
        self.get_private_key(key_id, password)

        priv_path = os.path.join(self._priv_dir, f"{key_id}.pem")
        with open(priv_path, "rb") as src, open(dest_path, "wb") as dst:
            dst.write(src.read())

    # ── pregled prstena ───────────────────────────────────────────────────────

    def list_public_keys(self) -> list[dict]:
        """Vraća listu svih unosa (i par i samo-javni)."""
        return list(self._metadata)

    def list_private_keys(self) -> list[dict]:
        """Vraća samo unose koji imaju privatni ključ."""
        return [e for e in self._metadata if e["has_private"]]

    # ── pristup ključevima ────────────────────────────────────────────────────

    def get_public_key(self, key_id: str):
        """Vraća RSA javni ključ objekat. Greška ako key_id ne postoji."""
        self._find_entry(key_id)
        pub_path = os.path.join(self._pub_dir, f"{key_id}.pem")
        with open(pub_path, "rb") as f:
            return serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )

    def get_private_key(self, key_id: str, password: str):
        """
        Vraća RSA privatni ključ objekat.
        Baca ValueError ako je lozinka netačna ili ključ nema privatni deo.
        """
        entry = self._find_entry(key_id)
        if not entry["has_private"]:
            raise ValueError(f"Ključ {key_id} nema privatni deo.")

        priv_path = os.path.join(self._priv_dir, f"{key_id}.pem")
        with open(priv_path, "rb") as f:
            pem_data = f.read()

        try:
            return serialization.load_pem_private_key(
                pem_data,
                password=password.encode("utf-8"),
                backend=default_backend(),
            )
        except (ValueError, TypeError) as e:
            raise ValueError("Netačna lozinka ili oštećen ključ.") from e

    def get_entry(self, key_id: str) -> dict:
        """Vraća metapodatke za dati Key ID."""
        return dict(self._find_entry(key_id))

    # ── interni pomoćni metodi ────────────────────────────────────────────────

    def _find_entry(self, key_id: str) -> dict:
        for e in self._metadata:
            if e["key_id"] == key_id:
                return e
        raise KeyError(f"Ključ sa ID-jem '{key_id}' nije pronađen u prstenu.")

    def _write_private_pem(self, key_id: str, private_key, password: str):
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                password.encode("utf-8")
            ),
        )
        path = os.path.join(self._priv_dir, f"{key_id}.pem")
        with open(path, "wb") as f:
            f.write(pem)

    def _write_public_pem(self, key_id: str, public_key):
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        path = os.path.join(self._pub_dir, f"{key_id}.pem")
        with open(path, "wb") as f:
            f.write(pem)