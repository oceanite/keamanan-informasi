#!/usr/bin/env python3
import socket
import threading
import struct
import json

HOST = '0.0.0.0'
PORT = 9000

clients = {}   # "A": socket, "B": socket

def recv_all(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_framed(sock):
    header = recv_all(sock, 4)
    if not header:
        return None
    (length,) = struct.unpack('>I', header)
    return recv_all(sock, length)


def send_framed(sock, data):
    header = struct.pack('>I', len(data))
    sock.sendall(header + data)


def handle_client(role, sock):
    print(f"[+] {role} terhubung.")

    try:
        while True:
            data = recv_framed(sock)
            if data is None:
                print(f"[-] {role} terputus.")
                break

            msg = json.loads(data.decode())

            #menentukan role
            peer = "A" if role == "B" else "B"

            #kalau peer belum ada → JANGAN tutup koneksi
            if peer not in clients:
                print(f"[SERVER] Peer {peer} belum terhubung. Menunggu...")
                continue

            #jika peer sudah ada lakukan forward
            try:
                send_framed(clients[peer], data)
            except:
                print("[SERVER] Gagal mengirim ke peer.")
                continue

    except Exception as e:
        print("[ERR]", e)

    finally:
        print(f"[SERVER] Membersihkan {role}.")
        if role in clients:
            del clients[role]
        sock.close()


def main():
    print(f"[SERVER] Listening di {HOST}:{PORT}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(5)

    while True:
        conn, addr = s.accept()

        #frame pertama harus pubkey berisi role
        first = recv_framed(conn)
        if first is None:
            conn.close()
            continue

        try:
            msg = json.loads(first.decode())
        except:
            conn.close()
            continue

        role = msg.get("role")

        if role not in ("A","B"):
            conn.close()
            continue

        #simpan client
        clients[role] = conn

        #forward pubkey ke peer jika peer sudah ada
        peer = "A" if role == "B" else "B"
        if peer in clients:
            send_framed(clients[peer], first)

        # jalankan thread
        thread = threading.Thread(target=handle_client, args=(role, conn), daemon=True)
        thread.start()


if __name__ == "__main__":
    main()
