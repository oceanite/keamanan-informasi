#!/usr/bin/env python3
import socket
import threading
import struct
import argparse
import sys

# pakai des.py yang sudah kamu paste (harus ada fungsi encrypt_cbc/decrypt_cbc)
from des import encrypt_cbc, decrypt_cbc

def recv_all(sock, n):
    """Read exactly n bytes or return None if connection closed."""
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def send_encrypted(sock: socket.socket, key: bytes, plaintext: bytes, debug: bool=False):
    """Encrypt plaintext using encrypt_cbc from des.py and send framed packet."""
    payload = encrypt_cbc(plaintext, key)  # returns iv + ciphertext
    header = struct.pack('>I', len(payload))
    if debug:
        print(f"[DEBUG send] len={len(payload)} hex={payload.hex()}")
    sock.sendall(header + payload)

def recv_loop(sock: socket.socket, key: bytes, debug: bool=False):
    """Continuously receive framed messages, try decrypt, show plaintext or garbage."""
    try:
        while True:
            header = recv_all(sock, 4)
            if not header:
                print("\n[!] Server menutup koneksi.")
                break
            (length,) = struct.unpack('>I', header)
            data = recv_all(sock, length)
            if data is None:
                print("\n[!] Server menutup koneksi (payload).")
                break

            if debug:
                print(f"[DEBUG recv] len={len(data)} hex={data.hex()}")

            # coba decrypt dengan key; kalau gagal tampilkan garbage hex
            try:
                plaintext = decrypt_cbc(data, key)  # may raise ValueError on padding
                # tampilkan sebagai utf-8 jika memungkinkan, otherwise fallback hex
                try:
                    text = plaintext.decode('utf-8')
                except Exception:
                    text = plaintext.decode('latin1', errors='replace')
            except Exception as e:
                # jika gagal dekripsi (biasanya wrong key / invalid padding) -> tampilkan garbage
                print(f"\n[!] Decrypt failed ({e}). Menampilkan payload sebagai hex (garbage).")
                print(f"[PEER - GARBAGE hex]: {data.hex()}")
                print("[KAMU]: ", end='', flush=True)
                continue

            print(f"\n[PEER]: {text}\n[KAMU]: ", end='', flush=True)

            # jika peer mengirim QUIT sebagai plaintext, berhenti
            if isinstance(text, str) and text.strip().upper() == "QUIT":
                print("[.] Peer requested QUIT. Closing receiver.")
                break
    except Exception as e:
        print(f"\n[!] Error di recv_loop: {e}")
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except:
            pass
        sock.close()

def send_loop(sock: socket.socket, key: bytes, debug: bool=False):
    """Read input and send encrypted messages. Quit on 'QUIT'."""
    try:
        while True:
            try:
                msg = input("[KAMU]: ")
            except EOFError:
                # Ctrl-D / EOF
                msg = "QUIT"
                print("QUIT (EOF)")

            if msg is None:
                continue
            if msg == "":
                continue

            try:
                send_encrypted(sock, key, msg.encode('utf-8'), debug=debug)
            except Exception as e:
                print(f"[!] Gagal mengirim pesan: {e}")
                break

            if msg.strip().upper() == "QUIT":
                # kirim lalu keluar
                break
    except Exception as e:
        print(f"[!] Error di send_loop: {e}")
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except:
            pass
        sock.close()

def main():
    parser = argparse.ArgumentParser(description="DES-from-scratch client (CBC)")
    parser.add_argument('--host', required=True, help='Server IP')
    parser.add_argument('--port', type=int, default=45000, help='Server port')
    parser.add_argument('--key', required=True, help='DES key (8 characters)')
    parser.add_argument('--debug', action='store_true', help='Show debug hex of payloads')
    args = parser.parse_args()

    key = args.key.encode('utf-8')
    if len(key) != 8:
        print("Error: key harus 8 byte (8 karakter).")
        sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((args.host, args.port))
    except Exception as e:
        print(f"Error: tidak bisa connect ke {args.host}:{args.port} -> {e}")
        sys.exit(1)

    print(f"[+] Terhubung ke {args.host}:{args.port}")

    t_recv = threading.Thread(target=recv_loop, args=(sock, key, args.debug), daemon=True)
    t_send = threading.Thread(target=send_loop, args=(sock, key, args.debug), daemon=True)

    t_recv.start()
    t_send.start()

    # tunggu sampai keduanya selesai
    t_send.join()
    # after send loop exits (user sent QUIT), we allow recv thread to finish gracefully
    try:
        t_recv.join(timeout=2.0)
    except:
        pass

    print("[.] Client selesai.")

if __name__ == "__main__":
    main()
