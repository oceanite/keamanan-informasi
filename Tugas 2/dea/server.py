import socket
import threading
import struct
import argparse

BLOCK_SIZE = 8
clients = []
clients_lock = threading.Lock()

#padding utk menambah data agar sesuai dgn ukuran block DES
def pad(b:bytes)->bytes:
  pad_len = BLOCK_SIZE - (len(b)%BLOCK_SIZE)
  return b + bytes([pad_len]*pad_len)


#unpadding utk menghilangkan padding setelah dekripsi
def unpad(b:bytes)->bytes:
  if not b:
    raise ValueError("Input data is empty")
  pad_len = b[-1]
  if pad_len < 1 or pad_len > BLOCK_SIZE:
    raise ValueError("Invalid padding length")
  return b[:-pad_len]

#fungsi utk enkripsi dgn DES dlm mode CBC (Cipher Block Chaining)
#def encrypt_pesan(key:bytes, plaintext:bytes)->bytes:
#  iv = get_random_bytes(BLOCK_SIZE)
#  cipher = DES.new(key, DES.MODE_CBC, iv)
#  ct = cipher.encrypt(pad(plaintext))
#  return iv + ct  #gabung iv dan ciphertext

#fungsi utk dekripsi pesan yg diterima dari client
#def decrypt_pesan(key:bytes, ciphertext:bytes)->bytes:
#  if len(ciphertext) < BLOCK_SIZE:
#    raise ValueError("Ciphertext is too short to contain IV") #cek panjang ciphertext
#  iv = ciphertext[:BLOCK_SIZE]
#  ct = ciphertext[BLOCK_SIZE:]    
#  cipher = DES.new(key, DES.MODE_CBC, iv)
#  pt = unpad(cipher.decrypt(ct))
#  return pt

def recv_until(sock, n):
    data = b''
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            break
        data += part
    return data

# teruskan pesan ke semua client kecuali pengirim
def forward_to_others(sender_sock, header_and_payload):
    with clients_lock:
        for c in clients:
            if c is sender_sock:
                continue
            try:
                c.sendall(header_and_payload)
            except Exception:
                # abaikan error pengiriman
                pass

#kirim pesan terenkripsi ke server
#def send_encrypted(sock, key:bytes, plaintext:bytes):
#    payload = encrypt_pesan(key, plaintext)
#    header = struct.pack('>I', len(payload))
#    sock.sendall(header + payload)

#stanby terima pesan dari server secara terus menerus
#def recv_loop(sock:socket.socket, key:bytes):
#    try:
#        while True:
#            header = recv_until(sock,4)
#           if not header:
#                print("Koneksi ditutup oleh server.")
#                break
#            (length,) = struct.unpack('>I', header)
#            data = recv_until(sock, length)
#            if data is None:
#                print("Koneksi ditutup oleh server.")
#                break
#            try:
#                plaintext = decrypt_pesan(key, data)
#            except Exception as e:
#                print(f"\n[!] Decrypt error: {e}\n[YOU]: ", end='', flush=True)
#                continue
#            text = plaintext.decode(errors='replace')
#            print(f"\n[SERVER]: {text}\n[YOU]: ", end='', flush=True)
#            if text.strip().upper() == "QUIT":
#                print("Server telah mengakhiri koneksi.")
#                break
#    except Exception as e:
#        print(f"[!]Error {e}")
#    finally:
#        try:
#            sock.shutdown(socket.SHUT_RDWR)
#        except:
#            pass
#        sock.close()

#def send_loop(sock:socket.socket, key:bytes):
#    try:
#        while True:
#            msg = input("[YOU]: ")
#            if not msg:
#                continue
#            send_encrypted(sock, key, msg.encode())
#            if msg.strip().upper() == "QUIT":
#                break
#    except Exception as e:
#        print(f"[!]Error {e}")
#    finally:
#        try:
#            sock.shutdown(socket.SHUT_RDWR)
#        except:
#            pass
#        sock.close() 

def process_client(conn, addr):
    print(f"Connected from {addr}")
    try:
        while True:
            header = recv_until(conn,4)
            if not header:
                print(f"[-] Client disconnected: {addr}")
                break
            (length,)= struct.unpack('>I', header)
            data = recv_until(conn, length)
            if data is None:
                print(f"[-] Client disconnected: {addr}")
                break
            # teruskan pesan ke client lain
            header_and_payload = header + data
            forward_to_others(conn, header_and_payload)
    
    except Exception as e:
        print(f"[!] Error with client {addr}: {e}")
    finally:
        with clients_lock:
            if conn in clients:
                clients.remove(conn)
        try:
            conn.close()
        except:
            pass
        print(f"[-] Connection from {addr} closed.")


def main():
    parser = argparse.ArgumentParser(description="DES Server (forward only)")
    parser.add_argument('--host', default='0.0.0.0', help='Bind address')
    parser.add_argument('--port', type=int, default=45000, help='Bind port')
    #parser.add_argument('--key', required=True, help='DES Key (8 karakter)')   
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(10)

    print(f"Server listening on {args.host}:{args.port}")
    #key=args.key.encode()
    #if len(key) != 8:
    #   raise SystemExit("DES key must be 8 bytes long.")

    try:
        while True:
            connection, address = sock.accept()
            with clients_lock:
                clients.append(connection)
            t = threading.Thread(target=process_client, args=(connection, address), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("Server shutting down.")         
    finally:
        with clients_lock:
            for c in clients:
                try:
                    c.close()
                except:
                    pass
        sock.close()

if __name__ == "__main__":
    main()