import base64
import zlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib

from messaging.crypt import getAlgorithm
from messaging.models.headers import AuthHeader, EncryptionHeader, CompressionHeader, Radix64Header, PlainHeader
from messaging.models.pgpmessage import PGPMessage, read_message, write_message

"""
plaintext - payload koji se kodira 
private_key - RSA privatni kljuc za autentikaciju, ako je null onda auth disabled
public_key + session key - RSA javni kljuc za enkripciju kljuca sesije + sam kljuc sesije, koristi se za tajnost, null ako tajnost nije ukljucena
zip - boolean flag da li zipujemo 
radix - boolean flag da li radimno konverziju u radix64
"""


def PGPEncode(output_file,plaintext, private_key, signer_id, session_key, recipient_id, public_key, algorithm, zip, radix):
    plainHeader = PlainHeader()
    message = PGPMessage(plainHeader, plaintext)

    # auth0
    if private_key is not None:
        # auth je plaintext || RSA(hash(plaintext))
        hash = hashlib.sha1(message.content).digest()
        encrypted_hash = private_key.sign(hash, padding.PKCS1v15(), hashes.SHA1())
        header = AuthHeader(signer_id, encrypted_hash)
        print(header)
        print(message.content)
        message = PGPMessage(header, message.content)

    if session_key is not None and public_key is not None and algorithm is not None:
        text = message.to_bytes()

        # ovo sad kriptujemo koristeci session key i odg algoritam, onda session key enkriptujemo sa RSA public i stavljamo u header
        algo = getAlgorithm(algorithm)

        encrypted_text = algo.encrypt(text, session_key)
        encrypted_session_key = public_key.encrypt(session_key, padding.PKCS1v15())

        header = EncryptionHeader(algorithm, encrypted_session_key, recipient_id)

        message = PGPMessage(header, encrypted_text)

    if zip:
        zipped = zlib.compress(message.to_bytes(), 9)

        header = CompressionHeader()

        message = PGPMessage(header, zipped)

    if radix:
        radix_msg = base64.b64encode(message.to_bytes())

        header = Radix64Header()

        message = PGPMessage(header, radix_msg)


    write_message(output_file, message)
    return message


def PGPDecode(filePath: str, password):
    message = read_message(filePath)

    while not isinstance(message.header, PlainHeader):
        message = message.decodeContent(password)

    print(message.to_dict())
    return message
