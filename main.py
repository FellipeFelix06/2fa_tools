import pyotp
from Crypto.Cipher import AES
from pathlib import Path
import sqlite3
import time
import pyfiglet
import os
import hashlib

PATH_DB = Path(__file__).parent / '2fa.sqlite'

texto = '2FA TOOLS'
arte = pyfiglet.figlet_format(texto)

def encrypt(texto_plano: str, chave_criptografia):
    texto_plano_bytes = texto_plano.encode('utf8')
    aes_obj = AES.new(chave_criptografia, AES.MODE_GCM)
    texto_cifrado, tag = aes_obj.encrypt_and_digest(texto_plano_bytes)
    return aes_obj.nonce.hex() + tag.hex() + texto_cifrado.hex()

def decrypt(texto_cifrado_hex, chave_aes_bytes):
    texto_cifrado_bytes = bytes.fromhex(texto_cifrado_hex)
    nonce = texto_cifrado_bytes[:16]
    tag = texto_cifrado_bytes[16:32]
    texto_encriptado = texto_cifrado_bytes[32:]
    aes_obj = AES.new(chave_aes_bytes, AES.MODE_GCM, nonce=nonce)
    texto_decifrado_bytes = aes_obj.decrypt_and_verify(texto_encriptado, tag)
    return texto_decifrado_bytes.decode()

def registrar():
    conn = sqlite3.connect(PATH_DB)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pass (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        salt TEXT NOT NULL,
        hash TEXT NOT NULL
    )
    """)

    conn.commit()

    senha = input("Digite uma senha: ").encode()

    if len(senha) not in (16, 24, 32):
        print("Senha deve ter 16 24 ou 32 bytes")
        return

    salt = os.urandom(16)
    hash_senha = hashlib.sha256(senha + salt).hexdigest()

    cursor.execute("INSERT INTO pass (salt, hash) VALUES (?, ?)", 
                   (salt.hex(), hash_senha))
    conn.commit()

    cursor.close()
    conn.close()
    print("Registro concluído.")

def login():
    conn = sqlite3.connect(PATH_DB)
    cursor = conn.cursor()
    
    cursor.execute("SELECT salt, hash FROM pass LIMIT 1")
    row = cursor.fetchone()

    if not row:
        print("Nenhuma senha Salva")
        return
    
    salt, hash_db = row
    senha_login = input("Digite a senha: ").encode()
    hash_teste = hashlib.sha256(senha_login + bytes.fromhex(salt)).hexdigest()

    if hash_teste == hash_db:
        print("Logado!")
        chave_aes = hashlib.sha256(senha_login + bytes.fromhex(salt)).digest()
        cursor.close()
        conn.close()
        return chave_aes
    else:
        print("Senha incorreta.")
        cursor.close()
        conn.close()
        return False


def consulta(opcao, chave_aes):
    conn = sqlite3.connect(PATH_DB)
    cursor = conn.cursor()

    cursor.execute("""CREATE TABLE IF NOT EXISTS "2fa" (
    id INTEGER PRIMARY KEY,
    OTP TEXT, \
    service TEXT
    )
    """)

    conn.commit()

    if opcao == '1':
        cursor.execute("""SELECT id, OTP, service FROM "2fa"
        """)
        all = cursor.fetchall()

        if all == []:
            print("Nenhum Serviço.")
            return
        else:
            for id, otp, service in all:
                print(f'{id}.', service)

            buscar = input("Digite um ID: ").strip()
            try:
                buscar_id = int(buscar)
            except ValueError:
                print("ID inválido.")
                return cursor.close(), conn.close()
            
            escolhido = next((r for r in all if r[0] == buscar_id), None)
            if not escolhido:
                print("Serviço inválido")
                return cursor.close(), conn.close()

            _, otp_encrypted, service = escolhido
            secret_key = decrypt(otp_encrypted, chave_aes).replace(" ", "")
            totp = pyotp.TOTP(secret_key)
            codigo_atual = totp.now()
            print("Código OTP:", codigo_atual)
            time.sleep(10)

    elif opcao == '2':
        otp_entrada = input("Digite o código OTP: ")
        servico_entrada = input("Digite o nome do Serviço: ")

        otp_encrypt = encrypt(otp_entrada, chave_aes)

        cursor.execute(""" INSERT INTO "2fa" (OTP, service) VALUES (?, ?)""", (otp_encrypt, servico_entrada))
        conn.commit()

    cursor.close()
    conn.close()

def menu():
    print(arte)
    opcao = input("1. Login / 2. Registrar: ")
    if opcao == '1':
        chave = login()
        opcao2 = input("1. Gerar código / 2. Registrar: ")
        consulta(opcao2, chave)
    elif opcao == '2':
        registrar()
    else:
        print("Opção inválida")

if __name__ == "__main__":
    menu()