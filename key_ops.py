"""
Operacije nad ključevima — tanak sloj iznad KeyRing klase.

Odgovornosti:
  - Validacija ulaznih podataka pre nego što se pozove KeyRing
  - Prevođenje grubih library grešaka u prilagođene PGPError podklase
  - Jedino mesto gde se importuje KeyRing — GUI i drugarov kod
    koriste SAMO funkcije iz ovog modula, ne KeyRing direktno

Upotreba:
    from key_ops import generate_key, get_public_key, get_private_key, list_keys
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend

from keyring import KeyRing
from exceptions import (
    WrongPasswordError,
    KeyNotFoundError,
    KeyAlreadyExistsError,
    InvalidKeyError,
    KeyHasNoPrivatePartError,
)

# Jedina instanca — svi je dele
_kr = KeyRing()


# ── generisanje ───────────────────────────────────────────────────────────────

def generate_key(name: str, email: str, key_size: int, password: str) -> str:
    """
    Generiše novi RSA par i čuva ga u prsten.
    Vraća Key ID.

    Greške:
        InvalidKeyError   — prazno ime/email, pogrešna veličina, prazna lozinka
    """
    name = name.strip()
    email = email.strip()

    if not name:
        raise InvalidKeyError("Ime ne sme biti prazno.")
    if not email or "@" not in email:
        raise InvalidKeyError("Unesite ispravnu e-mail adresu.")
    if key_size not in (1024, 2048):
        raise InvalidKeyError("Veličina ključa mora biti 1024 ili 2048 bita.")
    if not password:
        raise InvalidKeyError("Lozinka ne sme biti prazna.")

    return _kr.generate_key_pair(name, email, key_size, password)


# ── brisanje ──────────────────────────────────────────────────────────────────

def delete_key(key_id: str):
    """
    Briše ključ (ili par) iz prstena.

    Greške:
        KeyNotFoundError  — key_id ne postoji
    """
    try:
        _kr.delete_key(key_id)
    except KeyError:
        raise KeyNotFoundError(key_id)


# ── uvoz ──────────────────────────────────────────────────────────────────────

def import_public_key(pem_path: str, name: str, email: str) -> str:
    """
    Uvozi javni ključ iz PEM fajla.
    Vraća Key ID.

    Greške:
        InvalidKeyError        — neispravan PEM ili prazni podaci
        KeyAlreadyExistsError  — isti ključ već postoji
    """
    name = name.strip()
    email = email.strip()

    if not name:
        raise InvalidKeyError("Ime ne sme biti prazno.")
    if not email or "@" not in email:
        raise InvalidKeyError("Unesite ispravnu e-mail adresu.")

    try:
        return _kr.import_public_key(pem_path, name, email)
    except ValueError as e:
        msg = str(e)
        if "već postoji" in msg:
            # izvuci key_id iz poruke ili ostavi prazan
            raise KeyAlreadyExistsError()
        raise InvalidKeyError(f"Neispravan PEM fajl: {e}") from e
    except (TypeError, UnicodeDecodeError, Exception) as e:
        raise InvalidKeyError(f"Nije moguće učitati ključ: {e}") from e


def import_key_pair(pem_path: str, password: str, new_password: str) -> str:
    """
    Uvozi par ključeva iz enkriptovanog PEM fajla.
    Vraća Key ID.

    Greške:
        WrongPasswordError     — pogrešna lozinka fajla
        InvalidKeyError        — neispravan PEM
        KeyAlreadyExistsError  — isti ključ već postoji
    """
    if not new_password:
        raise InvalidKeyError("Nova lozinka ne sme biti prazna.")

    try:
        return _kr.import_key_pair(pem_path, password, new_password)
    except ValueError as e:
        msg = str(e)
        if "već postoji" in msg:
            raise KeyAlreadyExistsError()
        # cryptography baca ValueError i za pogrešnu lozinku
        if "password" in msg.lower() or "decrypt" in msg.lower() or "Bad decrypt" in msg.lower():
            raise WrongPasswordError()
        raise InvalidKeyError(f"Neispravan PEM fajl: {e}") from e
    except (TypeError, UnicodeDecodeError, Exception) as e:
        raise InvalidKeyError(f"Nije moguće učitati par ključeva: {e}") from e


# ── izvoz ─────────────────────────────────────────────────────────────────────

def export_public_key(key_id: str, dest_path: str):
    """
    Izvozi javni ključ u PEM fajl.

    Greške:
        KeyNotFoundError  — key_id ne postoji
    """
    try:
        _kr.export_public_key(key_id, dest_path)
    except KeyError:
        raise KeyNotFoundError(key_id)


def export_key_pair(key_id: str, password: str, dest_path: str):
    """
    Izvozi ceo par u enkriptovani PEM fajl.
    Proverava lozinku pre izvoza.

    Greške:
        KeyNotFoundError         — key_id ne postoji
        KeyHasNoPrivatePartError — nema privatni deo
        WrongPasswordError       — pogrešna lozinka
    """
    try:
        _kr.export_key_pair(key_id, password, dest_path)
    except KeyError:
        raise KeyNotFoundError(key_id)
    except ValueError as e:
        msg = str(e)
        if "nema privatni deo" in msg:
            raise KeyHasNoPrivatePartError(key_id)
        raise WrongPasswordError(key_id)


# ── pregled prstena ───────────────────────────────────────────────────────────

def list_keys() -> list[dict]:
    """
    Vraća sve unose iz prstena (i parovi i samo-javni).

    Svaki unos je rečnik:
        key_id, fingerprint, name, email, key_size,
        created_at, has_private
    """
    return _kr.list_public_keys()


def list_private_keys() -> list[dict]:
    """Vraća samo unose koji imaju privatni ključ."""
    return _kr.list_private_keys()


def get_entry(key_id: str) -> dict:
    """
    Vraća metapodatke za jedan ključ.

    Greška:
        KeyNotFoundError — key_id ne postoji
    """
    try:
        return _kr.get_entry(key_id)
    except KeyError:
        raise KeyNotFoundError(key_id)


# ── pristup ključevima (za drugarov modul) ────────────────────────────────────

def get_public_key(key_id: str):
    """
    Vraća RSA javni ključ objekat.
    Koristi drugarov modul za enkripciju i verifikaciju potpisa.

    Greška:
        KeyNotFoundError — key_id ne postoji
    """
    try:
        return _kr.get_public_key(key_id)
    except KeyError:
        raise KeyNotFoundError(key_id)


def get_private_key(key_id: str, password: str):
    """
    Vraća RSA privatni ključ objekat.
    Koristi drugarov modul za dekripciju i potpisivanje.

    Greške:
        KeyNotFoundError         — key_id ne postoji
        KeyHasNoPrivatePartError — nema privatni deo
        WrongPasswordError       — pogrešna lozinka
    """
    try:
        return _kr.get_private_key(key_id, password)
    except KeyError:
        raise KeyNotFoundError(key_id)
    except ValueError as e:
        msg = str(e)
        if "nema privatni deo" in msg:
            raise KeyHasNoPrivatePartError(key_id)
        raise WrongPasswordError(key_id)