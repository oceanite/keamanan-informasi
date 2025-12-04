#!/usr/bin/env python3
import socket
import threading
import struct
import argparse
import sys
import base64
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# DES CBC dari tugasmu sebelumnya
from des import encrypt_cbc, decrypt_cbc


# ----------------------
# Helper I/O
# ----------------------
def recv_all(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def send_framed(sock, payload_bytes):
    header = struct.pack('>I', len(payload_bytes))
    sock.sendall(header + payload_bytes)


def recv_framed(sock):
    header = recv_all(sock, 4)
    if not header:
        return None
    (length,) = struct.unpack('>I', header)
    return recv_all(sock, length)


# ----------------------
# RSA Helper
# ----------------------
def rsa_encrypt(pubkey, data_bytes):
    cipher = PKCS1_OAEP.new(pubkey)
    return cipher.encrypt(data_bytes)


def rsa_decrypt(privkey, enc_bytes):
    cipher = PKCS1_OAEP.new(privkey)
    return cipher.decrypt(enc_bytes)


#protokol pubkey dan sessionkey
def send_public_key(sock, role, pubkey):
    msg = {
        "type": "PUBKEY",
        "role": role,
        "data": base64.b64encode(pubkey.export_key()).decode()
    }
    send_framed(sock, json.dumps(msg).encode())


def send_session_key(sock, role, enc_session_key):
    msg = {
        "type": "SESSIONKEY",
        "role": role,
        "data": base64.b64encode(enc_session_key).decode()
    }
    send_framed(sock, json.dumps(msg).encode())


def recv_loop(sock, des_key_box, rsa_priv):
    """
    des_key_box adalah dict yang akan berisi session key DES (8 byte)
    {"key": None atau bytes}
    """
    try:
        while True:
            raw = recv_framed(sock)
            if raw is None:
                print("\n[!] Server menutup koneksi.")
                break

            msg = json.loads(raw.decode())
            mtype = msg.get("type", "")

            #pubkey dari peer
            if mtype == "PUBKEY":
                print("[INFO] Menerima PUBKEY dari peer.")
                peer_pub_bytes = base64.b64decode(msg["data"])
                des_key_box["peer_public_key"] = RSA.import_key(peer_pub_bytes)
                continue

            #sessionkey terenkripsi
            if mtype == "SESSIONKEY":
                print("[INFO] Menerima SESSIONKEY terenkripsi ... decrypting ...")
                enc = base64.b64decode(msg["data"])
                try:
                    des_key_box["key"] = rsa_decrypt(rsa_priv, enc)
                    print("[INFO] SESSION KEY DES berhasil didekripsi & disimpan.")
                except Exception as e:
                    print("[!] ERROR decrypt SESSIONKEY:", e)
                continue

            #data terenkripsi (DES)
            if mtype == "DATA":
                if des_key_box["key"] is None:
                    print("[!] DATA diterima tapi session key belum ada (abaikan).")
                    continue

                encrypted_payload = base64.b64decode(msg["data"])
                try:
                    pt = decrypt_cbc(encrypted_payload, des_key_box["key"])
                    try:
                        text = pt.decode()
                    except:
                        text = pt.decode("latin1")
                    print(f"\n[PEER] {text}\n[KAMU]: ", end="", flush=True)
                except Exception as e:
                    print("[!] Gagal decrypt DATA:", e)
                continue

    except Exception as e:
        print("[!] Error recv_loop:", e)
    finally:
        sock.close()

#send loop
def send_loop(sock, des_key_box, role):
    try:
        while True:
            msg = input("[KAMU]: ")
            if not msg:
                continue

            if msg.strip().upper() == "QUIT":
                sys.exit(0)

            if des_key_box["key"] is None:
                print("[!] Belum ada session key, tunggu negotiation.")
                continue

            encrypted = encrypt_cbc(msg.encode(), des_key_box["key"])
            packet = {
                "type": "DATA",
                "role": role,
                "data": base64.b64encode(encrypted).decode()
            }
            send_framed(sock, json.dumps(packet).encode())

    except:
        pass
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=45000)
    parser.add_argument("--role", required=True, help="A atau B")
    parser.add_argument("--initiator", action="store_true",
                        help="Jika diset, client ini yang membuat DES session key")
    args = parser.parse_args()

    role = args.role.upper()
    if role not in ("A", "B"):
        print("role harus A atau B")
        sys.exit(1)

    #buat RSA key pair
    rsa_key = RSA.generate(2048)
    rsa_priv = rsa_key
    rsa_pub = rsa_key.publickey()

    print("[INFO] RSA keypair dibuat.")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.host, args.port))
    print("[+] Terhubung ke server.")

    #container untuk session key DES
    des_key_box = {"key": None, "peer_public_key": None}

    #kirim pubkey ke server
    send_public_key(sock, role, rsa_pub)

    t = threading.Thread(target=recv_loop, args=(sock, des_key_box, rsa_priv), daemon=True)
    t.start()

    #negotiation (jika initiator)
    if args.initiator:
        print("[INITIATOR] Menunggu peer public key...")
        while des_key_box["peer_public_key"] is None:
            pass

        session_key = get_random_bytes(8)   # DES key
        des_key_box["key"] = session_key

        print("[INITIATOR] Membuat session key DES dan mengenkripsi dengan RSA peer...")
        enc = rsa_encrypt(des_key_box["peer_public_key"], session_key)

        send_session_key(sock, role, enc)
        print("[INITIATOR] Session key terkirim. Sekarang aman memakai DES.")

    else:
        print("[NON-INITIATOR] Menunggu SESSIONKEY dari peer...")

    #setelah negotiation, masuk mode chat
    send_loop(sock, des_key_box, role)


if __name__ == "__main__":
    main()
