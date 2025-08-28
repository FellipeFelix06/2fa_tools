import pyotp
from Crypto.Cipher import AES
from pathlib import Path
import sqlite3
import base64
import time
import pyfiglet

PATH_DB = Path(__file__).parent / '2fa.sqlite'

texto = '2FA TOOLS'
arte = pyfiglet.figlet_format(texto)

def encrypt(texto_plano:str, chave_criptografia):
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

def consulta(opcao):
    conn = sqlite3.connect(PATH_DB)
    cursor = conn.cursor()
    if opcao == '1':
        total = 0
        print("")
        print("Serivços Salvos: ")
        cursor.execute('SELECT key_aes, OTP, service FROM "2fa"')
        rows = cursor.fetchall()
        for key, otp, service in rows:
            total += 1
            print(f'{total}.', service)
        print("")
        pesquisa = input("Serviço: ")
        cursor.execute(
            'SELECT key_aes, OTP, service FROM "2fa" WHERE service LIKE ?',
            (f'%{pesquisa}%',)
        )
        rows = cursor.fetchall()
        if not rows:
            print("Serviço inválido.")
            time.sleep(5)
        else:
            for chave, otp, service in rows:
                try:
                    chave_aes_bytes = base64.b64decode(chave)
                    if len(chave_aes_bytes) not in (16, 24, 32):
                        raise ValueError("A chave deve conter 16, 24 ou 32 bytes")

                    descriptografar_otp = decrypt(otp, chave_aes_bytes)

                    totp = pyotp.TOTP(descriptografar_otp)
                    otp_atual = totp.now()
                    print(f"OTP atual: {otp_atual}")
                    time.sleep(20)
                except Exception as e:
                    print(f"Erro ao processar registro: {e}")
                    time.sleep(5)
    elif opcao == '2':
        chave_criptografia = input("Chave criptografia: ").encode()

        if len(chave_criptografia) not in (16, 24, 32):
            print("A chave deve conter 16, 24 ou 32 bytes")
        else:
            chave_encodeb64 = base64.b64encode(chave_criptografia)

        chave_otp = input("chave OTP: ")
        criptografado = encrypt(chave_otp, chave_encodeb64)

        nome_servico = input("Nome do Seriviço (ex: google): ")
        cursor.execute(
            'INSERT INTO "2fa" (key_aes, OTP, service) VALUES (?, ?, ?)',
            (chave_encodeb64, criptografado, nome_servico)
        )
        conn.commit()
    else:
        print("Opção inválida.")
        time.sleep(3)

    cursor.close()
    conn.close()

def menu():
    print(arte)
    opcao = input("Digite sua opção (1. Gerar codigo / 2. Adicionar): ")
    consulta(opcao)

if __name__ == "__main__":
    menu()