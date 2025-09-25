import os
import sqlite3
import json
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


def derive_key_from_meta(password: str, salt: bytes, kdf_name: str, kdf_params: dict) -> bytes:
    """
    Deriva una clave (32 bytes) usando el KDF indicado en kdf_name y los parámetros kdf_params.
    Lanza RuntimeError si la bóveda requiere Argon2 pero argon2-cffi no está disponible.
    """
    pwd = password.encode("utf-8")

    if kdf_name == "argon2":
        if not HAS_ARGON2:
            raise RuntimeError("La bóveda fue creada con Argon2 pero argon2-cffi no está disponible. Instala argon2-cffi.")
        
        time_cost = int(kdf_params.get("time_cost", ARGON2_PARAMS["time_cost"]))
        memory_cost = int(kdf_params.get("memory_cost", ARGON2_PARAMS["memory_cost"]))
        parallelism = int(kdf_params.get("parallelism", ARGON2_PARAMS["parallelism"]))
        hash_len = int(kdf_params.get("hash_len", ARGON2_PARAMS["hash_len"]))
        return hash_secret_raw(
            secret=pwd,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=Type.ID,
        )
    elif kdf_name == "scrypt":
        length = int(kdf_params.get("length", SCRYPT_PARAMS["length"]))
        n = int(kdf_params.get("n", SCRYPT_PARAMS["n"]))
        r = int(kdf_params.get("r", SCRYPT_PARAMS["r"]))
        p = int(kdf_params.get("p", SCRYPT_PARAMS["p"]))
        kdf = Scrypt(salt=salt, length=length, n=n, r=r, p=p, backend=default_backend())
        return kdf.derive(pwd)
    else:
        raise ValueError(f"KDF desconocido en meta de bóveda: {kdf_name}")


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
    salt, kdf_name, kdf_params = get_vault_meta()
    master = getpass.getpass("Contraseña maestra: ")
    try:
        key = derive_key_from_meta(master, salt, kdf_name, kdf_params)
    except Exception as e:
        print(str(e))
        return
    
    nonce, ct = aes_encrypt(key, secret.encode("utf-8"))
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(f"INSERT INTO {ENTRIES_TABLE} (title, username, nonce, ciphertext, created_at) VALUES (?, ?, ?, ?, ?)",
                (title, username, nonce, ct, datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()
    print("Entrada añadida correctamente.")


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


def get_entry(entry_id: int):
    """
    Recupera y descifra una entrada específica por ID:
    - Pide la contraseña maestra.
    - Descifra el ciphertext usando la clave derivada y el nonce.
    - Muestra título, usuario, secreto y fecha.
    :param entry_id:
    :return:
    """
    salt, kdf_name, kdf_params = get_vault_meta()
    master = getpass.getpass("Contraseña maestra: ")
    try:
        key = derive_key_from_meta(master, salt, kdf_name, kdf_params)
    except Exception as e:
        print(str(e))
        return
    
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
        print("Error al descifrar: contraseña maestra incorrecta o datos corruptos.")
        return

    print(f"Título: {title}\nUsuario: {username}\nSecreto: {plain}\nCreado: {created_at}")


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
    salt_old, kdf_name, kdf_params = get_vault_meta()
    master_old = getpass.getpass("Contraseña maestra actual: ")
    try:
        key_old = derive_key_from_meta(master_old, salt_old, kdf_name, kdf_params)
    except Exception as e:
        print(str(e))
        return

    # nueva contraseña
    master_new = getpass.getpass("Nueva contraseña maestra: ")
    master_new_c = getpass.getpass("Confirmar nueva contraseña: ")
    if master_new != master_new_c:
        print("Contraseñas nuevas no coinciden. Abortando.")
        return

    salt_new = os.urandom(16)
    new_kdf_name = "argon2" if HAS_ARGON2 else "scrypt"
    new_kdf_params = ARGON2_PARAMS if HAS_ARGON2 else SCRYPT_PARAMS
    key_new = None
    try:
        key_new = derive_key_from_meta(master_new, salt_new, new_kdf_name, new_kdf_params)
    except Exception as e:
        print("Error al derivar nueva clave:", e)
        return

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
        cur.execute(f"UPDATE {ENTRIES_TABLE} SET nonce=?, ciphertext=? WHERE id=?", (nonce_new, ct_new, eid))

    cur.execute(f"UPDATE {VAULT_TABLE} SET salt=?, kdf=?, kdf_params=? WHERE id=1",
                (salt_new, new_kdf_name, json.dumps(new_kdf_params)))
    conn.commit()
    conn.close()
    print("Contraseña maestra cambiada con éxito.")


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
        print("Gestor de Contraseñas\n")
        print("| opcion       | Descripcion")
        print("----------------------------------------------------------")
        print("| init         | Para inicializar la bóveda de contraseñas")
        print("| list         | Para listart las contraseñas")
        print("| add          | Para Registrar nueva contraseña")
        print("| get ID       | Para obtener una cuenta por ID")
        print("| delete ID    | Para eliminar una cuenta por ID")
        print("| changemaster | Para actualizar la contraseña maestra")
        print("----------------------------------------------------------")
        print("python gestor.py [opcion]")
        print("----------------------------------------------------------")
        return

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
