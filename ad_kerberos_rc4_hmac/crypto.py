from Crypto.Random import get_random_bytes
from Crypto.Cipher import ARC4 as RC4
from Crypto.Hash import HMAC

import hashlib


def hash_ntlm(password: str) -> str:
    """
    NTLM / NT Hash
    """
    unicode = password.encode('UTF-16LE')
    nt = hashlib.new('md4', unicode)
    return nt.hexdigest()


def encrypt(data: bytes, key: str) -> bytes:
    """
    RC4-HMAC-MD5 Encrypt
    Based on: https://datatracker.ietf.org/doc/html/rfc4757
    """
    k1 = key.encode('UTF-8')

    # K2
    confounder = get_random_bytes(8)
    hmac_k2 = HMAC.new(k1, (13).to_bytes(4, 'little'))  # RC4-HMAC Key usage (13)
    k2 = hmac_k2.digest()

    # Checksum
    toenc = confounder + data
    hmac_checksum = HMAC.new(k2, toenc)
    checksum = hmac_checksum.digest()

    # K3
    hmac_k3 = HMAC.new(k2, checksum)
    k3 = hmac_k3.digest()

    # RC4
    rc4_result = RC4.new(k3)
    return checksum + rc4_result.encrypt(toenc)


def verify(encrypted: bytes, key: str) -> bool:
    k1 = key.encode('UTF-8')

    # K2
    hmac_k2 = HMAC.new(k1, (13).to_bytes(4, 'little'))
    k2 = hmac_k2.digest()

    # K3
    hmac_k3 = HMAC.new(k2, encrypted[:16])
    k3 = hmac_k3.digest()

    # RC4
    rc4 = RC4.new(k3)
    enc = rc4.decrypt(encrypted[16:])

    # Checksum
    hmac_checksum = HMAC.new(k2, enc)
    current_checksum = hmac_checksum.digest()
    checksum = encrypted[:16]
    return checksum == current_checksum


def decrypt(encrypted: bytes, key: str) -> bytes:
    k1 = key.encode('UTF-8')

    # K2
    hmac_k2 = HMAC.new(k1, (13).to_bytes(4, 'little'))
    k2 = hmac_k2.digest()

    # K3
    hmac_k3 = HMAC.new(k2, encrypted[:16])
    k3 = hmac_k3.digest()

    # RC4
    rc4 = RC4.new(k3)
    enc = rc4.decrypt(encrypted[16:])
    return enc[8:]


def random2key() -> str:
    key = get_random_bytes(16)  # 16 bytes key size
    return key.decode('latin1')  # Decoded in latin1 for serialization reasons
