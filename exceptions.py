"""
Prilagođene greške za PGP key management.

Hijerarhija:
    PGPError (base)
    ├── WrongPasswordError     — pogrešna lozinka za privatni ključ
    ├── KeyNotFoundError       — key_id ne postoji u prstenu
    ├── KeyAlreadyExistsError  — pokušaj uvoza duplikata
    ├── InvalidKeyError        — neispravan PEM fajl ili parametri
    └── KeyHasNoPrivatePartError — tražen privatni ključ koji ne postoji

Drugar importuje samo ono što mu treba:
    from exceptions import WrongPasswordError, KeyNotFoundError
"""


class PGPError(Exception):
    """Osnovna greška — hvataj ovu ako hoćeš sve odjednom."""
    pass


class WrongPasswordError(PGPError):
    """Netačna lozinka pri pristupu privatnom ključu."""
    def __init__(self, key_id: str = ""):
        self.key_id = key_id
        msg = f"Netačna lozinka za ključ {key_id}." if key_id else "Netačna lozinka."
        super().__init__(msg)


class KeyNotFoundError(PGPError):
    """Traženi Key ID ne postoji u prstenu."""
    def __init__(self, key_id: str = ""):
        self.key_id = key_id
        msg = f"Ključ '{key_id}' nije pronađen u prstenu." if key_id else "Ključ nije pronađen."
        super().__init__(msg)


class KeyAlreadyExistsError(PGPError):
    """Ključ sa istim Key ID-jem već postoji — sprečava duplikat."""
    def __init__(self, key_id: str = ""):
        self.key_id = key_id
        msg = f"Ključ '{key_id}' već postoji u prstenu." if key_id else "Ključ već postoji."
        super().__init__(msg)


class InvalidKeyError(PGPError):
    """
    Neispravan PEM fajl, pogrešna veličina ključa, ili drugi problem
    sa samim ključem (ne sa lozinkom).
    """
    pass


class KeyHasNoPrivatePartError(PGPError):
    """Pokušaj pristupa privatnom ključu koji nije uvezen kao par."""
    def __init__(self, key_id: str = ""):
        self.key_id = key_id
        msg = (f"Ključ '{key_id}' nema privatni deo — uvezen je samo javni ključ."
               if key_id else "Ovaj ključ nema privatni deo.")
        super().__init__(msg)