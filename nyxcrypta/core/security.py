"""
Security primitives for NyxCrypta: security levels and password-based
protection of private keys.

Private keys are never stored with a weak password-derived key: the password is
stretched with Argon2id (memory-hard, resistant to GPU/ASIC brute force) and the
resulting 256-bit key encrypts the PKCS8 key with AES-256-GCM.

Container layout (NyxCrypta key container, "NYXK", version 1):

    magic        4 bytes   b"NYXK"
    version      1 byte    1
    kdf          1 byte    1 = Argon2id
    time_cost    4 bytes   little-endian
    memory_cost  4 bytes   little-endian, in KiB
    parallelism  1 byte
    salt        16 bytes   random, unique per key
    nonce       12 bytes   random, unique per key
    ciphertext   n bytes   AES-256-GCM(PKCS8 DER) + 16-byte tag

The whole header (everything before the ciphertext) is the GCM additional
authenticated data: tampering with the KDF parameters, the salt or the nonce
makes decryption fail instead of silently weakening the key derivation.
"""
import base64
import os
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecurityLevel(Enum):
    STANDARD = 1  # RSA 2048
    HIGH = 2  # RSA 3072
    PARANOID = 3  # RSA 4096


@dataclass(frozen=True)
class Argon2Params:
    """Argon2id cost parameters. `memory_cost` is expressed in KiB."""
    time_cost: int
    memory_cost: int
    parallelism: int


# Cost of the private-key protection for each security level.
# STANDARD matches the second recommended option of RFC 9106 (64 MiB, t=3, p=4).
ARGON2_PARAMS = {
    SecurityLevel.STANDARD: Argon2Params(time_cost=3, memory_cost=64 * 1024, parallelism=4),
    SecurityLevel.HIGH: Argon2Params(time_cost=4, memory_cost=128 * 1024, parallelism=4),
    SecurityLevel.PARANOID: Argon2Params(time_cost=5, memory_cost=256 * 1024, parallelism=4),
}

# Bounds enforced when *reading* a key, so that a crafted key file cannot make
# the loader allocate gigabytes of memory or run for hours.
MAX_TIME_COST = 20
MAX_MEMORY_COST = 1024 * 1024  # 1 GiB
MAX_PARALLELISM = 16

MAGIC = b"NYXK"
CONTAINER_VERSION = 1
KDF_ARGON2ID = 1
KEY_SIZE = 32
SALT_SIZE = 16
NONCE_SIZE = 12
_HEADER_FMT = "<BBIIB"  # version, kdf, time_cost, memory_cost, parallelism
HEADER_SIZE = len(MAGIC) + struct.calcsize(_HEADER_FMT) + SALT_SIZE + NONCE_SIZE

ARMOR_LABEL = "NYXCRYPTA ENCRYPTED PRIVATE KEY"
_ARMOR_BEGIN = f"-----BEGIN {ARMOR_LABEL}-----"
_ARMOR_END = f"-----END {ARMOR_LABEL}-----"


def params_for_level(level: SecurityLevel) -> Argon2Params:
    return ARGON2_PARAMS[level]


def derive_key(password: bytes, salt: bytes, params: Argon2Params) -> bytes:
    """Derives a 256-bit key from a password with Argon2id."""
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


def _check_params(params: Argon2Params) -> None:
    if not 1 <= params.time_cost <= MAX_TIME_COST:
        raise ValueError("Unsupported Argon2 time cost in key file")
    if not 1 <= params.parallelism <= MAX_PARALLELISM:
        raise ValueError("Unsupported Argon2 parallelism in key file")
    if not 8 * params.parallelism <= params.memory_cost <= MAX_MEMORY_COST:
        raise ValueError("Unsupported Argon2 memory cost in key file")


def is_protected_blob(data: bytes) -> bool:
    """True if `data` is a binary NyxCrypta key container."""
    return data.startswith(MAGIC)


def is_armored(data: bytes) -> bool:
    """True if `data` is a PEM-armored NyxCrypta key container."""
    return _ARMOR_BEGIN.encode() in data


def protect_private_key(pkcs8_der: bytes, password: bytes,
                        params: Optional[Argon2Params] = None) -> bytes:
    """Encrypts an unencrypted PKCS8 DER private key with a password (Argon2id + AES-256-GCM)."""
    if not password:
        raise ValueError("A non-empty password is required to protect a private key")
    params = params or ARGON2_PARAMS[SecurityLevel.STANDARD]
    _check_params(params)

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    header = (
        MAGIC
        + struct.pack(_HEADER_FMT, CONTAINER_VERSION, KDF_ARGON2ID,
                      params.time_cost, params.memory_cost, params.parallelism)
        + salt
        + nonce
    )
    key = derive_key(password, salt, params)
    return header + AESGCM(key).encrypt(nonce, pkcs8_der, header)


def unprotect_private_key(blob: bytes, password: bytes) -> bytes:
    """Decrypts a NyxCrypta key container and returns the PKCS8 DER private key."""
    if not password:
        raise ValueError("A password is required to read this private key")
    if len(blob) < HEADER_SIZE + 16 or not is_protected_blob(blob):
        raise ValueError("Invalid or truncated NyxCrypta key container")

    offset = len(MAGIC)
    fixed = struct.calcsize(_HEADER_FMT)
    version, kdf, time_cost, memory_cost, parallelism = struct.unpack(
        _HEADER_FMT, blob[offset:offset + fixed])
    if version != CONTAINER_VERSION:
        raise ValueError(f"Unsupported key container version: {version}")
    if kdf != KDF_ARGON2ID:
        raise ValueError(f"Unsupported key derivation function: {kdf}")
    params = Argon2Params(time_cost, memory_cost, parallelism)
    _check_params(params)  # before deriving anything: bounds the work and memory

    offset += fixed
    salt = blob[offset:offset + SALT_SIZE]
    nonce = blob[offset + SALT_SIZE:HEADER_SIZE]
    header, ciphertext = blob[:HEADER_SIZE], blob[HEADER_SIZE:]

    key = derive_key(password, salt, params)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, header)
    except InvalidTag:
        raise ValueError("Incorrect password or corrupted key file") from None


def armor(blob: bytes) -> bytes:
    """Wraps a binary key container in a PEM-style text envelope."""
    body = base64.b64encode(blob).decode("ascii")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return ("\n".join([_ARMOR_BEGIN, *lines, _ARMOR_END]) + "\n").encode("ascii")


def dearmor(data: bytes) -> bytes:
    """Extracts the binary key container from its PEM-style text envelope."""
    try:
        text = data.decode("ascii")
        start = text.index(_ARMOR_BEGIN) + len(_ARMOR_BEGIN)
        end = text.index(_ARMOR_END, start)
        return base64.b64decode("".join(text[start:end].split()), validate=True)
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError(f"Invalid PEM-armored NyxCrypta key: {e}") from e
