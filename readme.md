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



