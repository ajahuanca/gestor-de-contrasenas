import os
import sys
import sqlite3
import json
import base64
import getpass
import argparse
from datetime import datetime, timezone


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


# --- Base de Datos y operaciones CRUD ---
def ensure_db():
    """
    Crea las tablas de SQLite si no existen:
    vault_meta: información de la bóveda (salt, KDF, parámetros).
    vault_entries: las entradas cifradas (título, usuario, nonce, ciphertext).
    :return:
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(f""" 
        CREATE TABLE IF NOT EXISTS {VAULT_TABLE} ( 
            id INTEGER PRIMARY KEY CHECK (id=1), 
            salt BLOB NOT NULL, 
            kdf TEXT NOT NULL, 
            kdf_params TEXT NOT NULL, 
            created_at TEXT NOT NULL 
        ) 
    """)
    cur.execute(f""" 
        CREATE TABLE IF NOT EXISTS {ENTRIES_TABLE} ( 
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            title TEXT NOT NULL, 
            username TEXT, 
            nonce BLOB NOT NULL, 
            ciphertext BLOB NOT NULL, 
            created_at TEXT NOT NULL 
        ) 
    """)
    conn.commit()
    conn.close()


def vault_exists() -> bool:
    """
    Verifica si la bóveda ya fue inicializada (si hay una fila en vault_meta).
    :return:
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(f"SELECT COUNT(*) FROM {VAULT_TABLE} WHERE id=1")
    row = cur.fetchone()
    conn.close()
    return row is not None and row[0] > 0


def init_vault():
    """
    Inicializa la bóveda por primera vez:
    - Pide una contraseña maestra y su confirmación.
    - Genera un salt aleatorio.
    - Guarda en vault_meta el salt, el KDF usado y los parámetros.
    - No guarda la contraseña en ningún lado.
    :return:
    """
    ensure_db()
    if vault_exists():
        print("La bóveda ya está inicializada.")
        return

    master = getpass.getpass("Nueva contraseña maestra: ")
    confirm = getpass.getpass("Confirmar contraseña: ")
    if master != confirm:
        print("Contraseñas no coinciden. Abortando.")
        return

    salt = os.urandom(16)
    kdf_name = "argon2" if HAS_ARGON2 else "scrypt"
    params = ARGON2_PARAMS if HAS_ARGON2 else SCRYPT_PARAMS
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(f"INSERT INTO {VAULT_TABLE} (id, salt, kdf, kdf_params, created_at) VALUES (1, ?, ?, ?, ?)",
                (salt, kdf_name, json.dumps(params), datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()
    print("Bóveda inicializada. No olvides tu contraseña maestra.")
    print("-------------------------------------------------------------")
    interactive_menu()


def get_vault_meta():
    """
    Devuelve los datos de la bóveda: (salt, kdf, kdf_params).
    Útil para derivar la clave maestra cuando se añaden o leen entradas.
    :return:
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(f"SELECT salt, kdf, kdf_params FROM {VAULT_TABLE} WHERE id=1")
    row = cur.fetchone()
    conn.close()
    if not row:
        raise RuntimeError("Bóveda no inicializada.")
    salt, kdf, kdf_params = row
    return salt, kdf, json.loads(kdf_params)


def add_entry():
    """
    Añade una entrada a la bóveda:
    - Pide título, usuario y secreto.
    - Solicita la contraseña maestra para derivar la clave.
    - Cifra el secreto con AES-GCM y guarda (nonce, ciphertext) en la tabla vault_entries.
    :return:
    """
    if not vault_exists():
        print("Inicializa la bóveda primero con: init")
        return
    title = input("Título (ej: correo personal): ")
    username = input("Usuario (opcional): ")
    secret = getpass.getpass("Secreto/Contraseña: ")
    salt, kdf, kdf_params = get_vault_meta()
    master = getpass.getpass("Contraseña maestra: ")
    key = derive_key(master, salt)
    nonce, ct = aes_encrypt(key, secret.encode("utf-8"))
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(f"INSERT INTO {ENTRIES_TABLE} (title, username, nonce, ciphertext, created_at) VALUES (?, ?, ?, ?, ?)",
                (title, username, nonce, ct, datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()
    print("Entrada añadida correctamente.")
    print("-----------------------------------------")
    interactive_menu()


def list_entries():
    """
    Muestra una lista de todas las entradas (ID, título, usuario y fecha) sin descifrar los secretos.
    :return:
    """
    ensure_db()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(f"SELECT id, title, username, created_at FROM {ENTRIES_TABLE} ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    if not rows:
        print("Sin entradas.")
        return
    for r in rows:
        print(f"{r[0]:>3} | {r[1]:30.30} | {r[2] or '-':20.20} | {r[3]}")
    print("--------------------------------------------------------------------------------------------")
    interactive_menu()


def get_entry(entry_id: int):
    """
    Recupera y descifra una entrada específica por ID:
    - Pide la contraseña maestra.
    - Descifra el ciphertext usando la clave derivada y el nonce.
    - Muestra título, usuario, secreto y fecha.
    :param entry_id:
    :return:
    """
    salt, kdf, kdf_params = get_vault_meta()
    master = getpass.getpass("Contraseña maestra: ")
    key = derive_key(master, salt)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(f"SELECT title, username, nonce, ciphertext, created_at FROM {ENTRIES_TABLE} WHERE id=?", (entry_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        print("Entrada no encontrada.")
        return
    title, username, nonce, ciphertext, created_at = row
    try:
        plain = aes_decrypt(key, nonce, ciphertext).decode("utf-8")
    except Exception as e:
        print(str(e))
        print("Error al descifrar: contraseña maestra incorrecta o datos corruptos.")
        return
    print(f"Título: {title}\nUsuario: {username}\nSecreto: {plain}\nCreado: {created_at}")
    print("---------------------------------------------------------------------------------------------------")
    interactive_menu()


def delete_entry(entry_id: int):
    """
    Elimina una entrada por ID de la base de datos.
    :param entry_id:
    :return:
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(f"DELETE FROM {ENTRIES_TABLE} WHERE id=?", (entry_id,))
    conn.commit()
    conn.close()
    print(f"Entrada {entry_id} eliminada (si existía).")
    print("-------------------------------------------")
    interactive_menu()


def change_master():
    """
    Cambia la contraseña maestra de la bóveda:
    - Pide contraseña actual y derivada.
    - Descifra todas las entradas con la clave vieja.
    - Genera nueva clave y salt.
    - Re-cifra todas las entradas con la nueva clave.
    - Actualiza vault_meta.
    :return:
    """
    if not vault_exists():
        print("Inicializa la bóveda primero con: init")
        return
    salt_old, kdf, kdf_params = get_vault_meta()
    master_old = getpass.getpass("Contraseña maestra actual: ")
    key_old = derive_key(master_old, salt_old)
    # pedir nueva
    master_new = getpass.getpass("Nueva contraseña maestra: ")
    master_new_c = getpass.getpass("Confirmar nueva contraseña: ")
    if master_new != master_new_c:
        print("Contraseñas nuevas no coinciden. Abortando.")
        return
    salt_new = os.urandom(16)
    key_new = derive_key(master_new, salt_new)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(f"SELECT id, nonce, ciphertext FROM {ENTRIES_TABLE}")
    rows = cur.fetchall()
    for r in rows:
        eid, nonce, ciphertext = r
        try:
            plain = aes_decrypt(key_old, nonce, ciphertext)
        except Exception:
            print("Error: contraseña maestra actual incorrecta o datos corruptos. Abortando.")
            conn.close()
            return
        nonce_new, ct_new = aes_encrypt(key_new, plain)
        cur.execute(f"UPDATE {ENTRIES_TABLE} SET nonce=?, ciphertext=? WHERE id=?",
                    (nonce_new, ct_new, eid))
        # actualizar meta
        cur.execute(f"UPDATE {VAULT_TABLE} SET salt=?, kdf=?, kdf_params=? WHERE id=1",
                    (salt_new, "argon2" if HAS_ARGON2 else "scrypt", json.dumps(ARGON2_PARAMS if HAS_ARGON2 else SCRYPT_PARAMS)))
        conn.commit()
        conn.close()
        print("Contraseña maestra cambiada con éxito.")
        print("---------------------------------------")
        interactive_menu()


def export_vault(path: str):
    """
    Exporta la base de datos completa (vault.db) a otra ubicación para backup.
    No necesita descifrar nada porque cada entrada ya está cifrada individualmente.
    :param path:
    :return:
    """
    conn = sqlite3.connect(DB_PATH)
    conn.close()
    with open(DB_PATH, "rb") as fsrc:
        data = fsrc.read()
    with open(path, "wb") as fdst:
        fdst.write(data)
        print(f"Exportado a {path}")


def interactive_menu():
    print("=== Gestor de Contraseñas ===")
    print("Selecciona una acción:")
    print("1. Inicializar bóveda")
    print("2. Agregar entrada")
    print("3. Listar entradas")
    print("4. Obtener entrada")
    print("5. Eliminar entrada")
    print("6. Cambiar contraseña maestra")
    print("7. Exportar bóveda")
    print("0. Salir")

    while True:
        choice = input("Opción [0-7]: ").strip()
        if choice in [str(i) for i in range(8)]:
            return choice
        else:
            print("Opción inválida. Intenta de nuevo.")


# Método principal para ejecutar el CLI
def main():
    """
    Analiza los argumentos de la línea de comandos
    (init, add, list, get, delete, changemaster, export)
    y llama a la función correspondiente.
    También asegura que la base de datos exista antes de cualquier operación.
    :return:
    """
    parser = argparse.ArgumentParser(description="Gestor de contraseñas - práctica criptografía")
    parser.add_argument("cmd", nargs="?", choices=["init", "add", "list", "get", "delete", "changemaster", "export"],
                        help="comando")
    parser.add_argument("arg", nargs="?", help="argumento opcional para algunos comandos (id o path)")
    args = parser.parse_args()

    ensure_db()
    cmd = args.cmd
    arg = args.arg

    if not cmd:
        choice = interactive_menu()
        mapping = {
            "1": "init",
            "2": "add",
            "3": "list",
            "4": "get",
            "5": "delete",
            "6": "changemaster",
            "7": "export",
            "0": None
        }
        cmd = mapping[choice]
        if cmd is None:
            print("Saliendo...")
            return
        if cmd in ["get", "delete", "export"]:
            arg = input("Ingresa el ID o path correspondiente: ").strip()

    if cmd == "init":
        init_vault()
    elif cmd == "add":
        add_entry()
    elif cmd == "list":
        list_entries()
    elif cmd == "get":
        if not arg:
            print("Usar: get <id>")
            return
        get_entry(int(arg))
    elif cmd == "delete":
        if not arg:
            print("Usar: delete <id>")
            return
        delete_entry(int(arg))
    elif cmd == "changemaster":
        change_master()
    elif cmd == "export":
        if not arg:
            print("Usar: export <path>")
            return
        export_vault(arg)


if __name__ == '__main__':
    main()
