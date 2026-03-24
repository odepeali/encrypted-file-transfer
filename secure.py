import sys
import socket
import ssl
import os
import time
import threading
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def generate_key_iv():
    key = os.urandom(32)  # AES-256 key
    iv = os.urandom(16)   # 128-bit IV
    return key, iv


def encrypt_file(file_path, key, iv):
    padder = padding.PKCS7(128).padder()

    with open(file_path, "rb") as f:
        data = f.read()

    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    enc_path = file_path + ".enc"

    with open(enc_path, "wb") as f:
        f.write(encrypted)

    return enc_path


def decrypt_file(enc_path, key, iv):

    with open(enc_path, "rb") as f:
        encrypted = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(encrypted) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    dec_path = enc_path.replace(".enc", ".dec")

    with open(dec_path, "wb") as f:
        f.write(data)

    return dec_path


def delete_after_time(file_paths, timeout=300):

    def delete_files():
        time.sleep(timeout)

        for path in file_paths:
            if os.path.exists(path):
                os.remove(path)
                print(f"Auto-deleted: {path}")

    threading.Thread(target=delete_files, daemon=True).start()


def run_server(file_path="secret.txt", port=4443, timeout=300):

    key, iv = generate_key_iv()

    print("Generated Key:", key.hex())
    print("Generated IV :", iv.hex())
    print("Send these securely to the client.")

    enc_path = encrypt_file(file_path, key, iv)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", port))
    sock.listen(1)

    print(f"Server listening on port {port}")

    with context.wrap_socket(sock, server_side=True) as ssl_sock:

        conn, addr = ssl_sock.accept()
        print("Connection from", addr)

        with open(enc_path, "rb") as f:

            while True:
                chunk = f.read(4096)
                if not chunk:
                    break

                conn.sendall(chunk)

        conn.close()

    delete_after_time([file_path, enc_path], timeout)

    print("File sent. Auto-deletion scheduled.")


def run_client(host="localhost", port=4443):

    key_hex = input("Enter Key (hex): ")
    iv_hex = input("Enter IV (hex): ")

    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    with context.wrap_socket(sock, server_hostname=host) as ssl_sock:

        ssl_sock.connect((host, port))

        print("Connected to server.")

        enc_path = "received.enc"

        with open(enc_path, "wb") as f:

            while True:
                chunk = ssl_sock.recv(4096)

                if not chunk:
                    break

                f.write(chunk)

    dec_path = decrypt_file(enc_path, key, iv)

    print("File decrypted to:", dec_path)


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage:")
        print("python secure_file_transfer.py server")
        print("python secure_file_transfer.py client")
        sys.exit(1)

    mode = sys.argv[1].lower()

    if mode == "server":
        run_server()

    elif mode == "client":
        run_client()

    else:
        print("Invalid mode. Use 'server' or 'client'.")