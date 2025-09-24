import os
import sys
import sqlite3
import json
import base64
import getpass
import argparse
from datetime import datetime


try:
    from argon2.low_level import hash_secret_raw, Type
    HAS_ARGON2 = True
except Exception:
    HAS_ARGON2 = False

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend


# Definicion de variables y parametros globales
DB_PATH = "vault.db"
VAULT_TABLE = "vault_meta"
ENTRIES_TABLE = "vault_entries"

ARGON2_PARAMS = {
    "time_cost": 2,
    "memory_cost": 2 ** 16,
    "parallelism": 1,
    "hash_len": 32,
}


SCRYPT_PARAMS = {
    "length": 32,
    "n": 2 ** 14,
    "r": 8,
    "p": 1,
}


# Definición de Helpers criptograficos
def derive_key_argon2(password: bytes, salt: bytes) -> bytes:
    """
    Se encarga de transformar la contraseña maestra del usuario en una clave criptográfica segura.
    :param password:
    :param salt:
    :return:
    """
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=ARGON2_PARAMS["time_cost"],
        memory_cost=ARGON2_PARAMS["memory_cost"],
        parallelism=ARGON2_PARAMS["parallelism"],
        hash_len=ARGON2_PARAMS["hash_len"],
        type=Type.ID,
    )


def derive_key_scrypt(password: bytes, salt: bytes) -> bytes:
    """
    Convierte una contraseña maestra en una clave criptográfica segura de tamaño fijo.
    :param password:
    :param salt:
    :return:
    """
    kdf = Scrypt(salt=salt, **SCRYPT_PARAMS, backend=default_backend())
    return kdf.derive(password)


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Determina qué KDF usar (argon2 o scrypt) y devuelve la clave derivada.
    :param password:
    :param salt:
    :return:
    """
    pwd = password.encode("utf-8")
    if HAS_ARGON2:
        return derive_key_argon2(pwd, salt)
    else:
        return derive_key_scrypt(pwd, salt)


def aes_encrypt(key: bytes, plaintext: bytes) -> (bytes, bytes):
    """
    Cifra un mensaje (plaintext) usando AES-256-GCM con la clave key.
    Genera un nonce aleatorio de 12 bytes y devuelve (nonce, ciphertext).
    :param key:
    :param plaintext:
    :return:
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ct


def aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Descifra un ciphertext usando AES-GCM con la clave y el nonce correspondientes.
    Garantiza confidencialidad y autenticidad (detecta modificaciones).
    :param key:
    :param nonce:
    :param ciphertext:
    :return:
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def main():
    print('iniciando')


if __name__ == '__main__':
    main()
