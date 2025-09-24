# Gestor de Contraseñas (Práctica de Criptografía)

**Archivo principal:**  
```
gestor.py
```  

Este proyecto es un **gestor de contraseñas en consola** que proporciona confidencialidad y autenticidad usando **AES-256-GCM** para cifrado y **Argon2** (o Scrypt) para derivar la clave maestra. Todos los secretos se guardan cifrados en una base de datos SQLite, sin almacenar la contraseña maestra en texto plano.

## Características

- Deriva la clave maestra usando **Argon2id** (preferido) o **Scrypt**.  
- Cifra cada entrada individual con **AES-256-GCM**, garantizando confidencialidad y autenticidad.  
- Persiste los secretos en una base de datos **SQLite**, sin texto plano.  
- Permite cambiar la contraseña maestra de forma segura, re-encriptando todas las entradas.  
- Comandos CLI para administración completa: inicializar, agregar, listar, obtener, eliminar, cambiar contraseña y exportar.

## Instalación

1. Clonar el repositorio o descargar el script:

```bash
git clone https://github.com/ajahuanca/gestor-de-contrasenas.git
cd gestor-contrasenas
```

2. Instalar dependencias:
```bash
pip install -r requirements.txt
-- Adicionalmente
pip install cryptography argon2-cffi
```
> Si argon2-cffi no está disponible, el gestor usará Scrypt automáticamente.

## Uso

### Inicializar la bóveda

```bash
python gestor.py init
```
* Solicita una contraseña maestra.
* Genera un salt único y crea la base de datos.

### Agregar una entrada
```bash
python gestor.py add
```
* Ingresa título, usuario y contraseña/secretos. 
* Solicita la contraseña maestra para cifrar el secreto.

### Listar entradas
```bash
python gestor.py list
```
* Muestra ID, título, usuario y fecha de creación de todas las entradas. 
* No descifra los secretos.

### Obtener y descifrar una entrada
```bash
python gestor.py get <id>
```
* Descifra y muestra el secreto de la entrada seleccionada. 
* Solicita la contraseña maestra.

### Eliminar una entrada
```bash
python gestor.py delete <id>
```
* Elimina la entrada seleccionada de forma permanente.

### Cambiar contraseña maestra
```bash
python gestor.py changemaster
```
* Solicita la contraseña actual. 
* Solicita nueva contraseña y confirma. 
* Re-encripta todas las entradas con la nueva clave.

### Exportar la bóveda
```bash
python gestor.py export <ruta_destino>
```
* Copia el archivo de base de datos cifrada a otra ubicación para backup.

## Seguridad

* La contraseña maestra nunca se guarda en disco. 
* Cada entrada tiene un nonce único para AES-GCM. 
* El salt y los parámetros del KDF son únicos por bóveda. 
* Argon2 y Scrypt usan parámetros conservadores para dificultar ataques de fuerza bruta. 
* Para backup seguro o compartir, exportar la base de datos y mantener el salt/parametros.

## Estructura de la base de datos
Tabla: **vault_meta**

| Campo       | Descripción                    |
| ----------- | ------------------------------ |
| id          | Siempre 1                      |
| salt        | Salt aleatorio para KDF        |
| kdf         | `argon2` o `scrypt`            |
| kdf\_params | Parámetros del KDF en JSON     |
| created\_at | Fecha de creación de la bóveda |

Tabla: **vault_entries**

| Campo       | Descripción                     |
| ----------- | ------------------------------- |
| id          | ID autoincremental              |
| title       | Título descriptivo              |
| username    | Usuario (opcional)              |
| nonce       | Nonce AES-GCM                   |
| ciphertext  | Secreto cifrado                 |
| created\_at | Fecha de creación de la entrada |
