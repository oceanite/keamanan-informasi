#!/usr/bin/env python3
# des.py
# Correct DES (16 rounds) implementation + CBC wrappers + PKCS#5 padding.
# Input/output in bytes. Key must be exactly 8 bytes.

from typing import List
import os

# ---------- Tables (standard DES tables) ----------
IP = [
  58,50,42,34,26,18,10,2,
  60,52,44,36,28,20,12,4,
  62,54,46,38,30,22,14,6,
  64,56,48,40,32,24,16,8,
  57,49,41,33,25,17,9,1,
  59,51,43,35,27,19,11,3,
  61,53,45,37,29,21,13,5,
  63,55,47,39,31,23,15,7
]

FP = [
  40,8,48,16,56,24,64,32,
  39,7,47,15,55,23,63,31,
  38,6,46,14,54,22,62,30,
  37,5,45,13,53,21,61,29,
  36,4,44,12,52,20,60,28,
  35,3,43,11,51,19,59,27,
  34,2,42,10,50,18,58,26,
  33,1,41,9,49,17,57,25
]

E = [
  32,1,2,3,4,5,
  4,5,6,7,8,9,
  8,9,10,11,12,13,
  12,13,14,15,16,17,
  16,17,18,19,20,21,
  20,21,22,23,24,25,
  24,25,26,27,28,29,
  28,29,30,31,32,1
]

S_BOX = [
# S1
[
14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
],
# S2
[
15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
],
# S3
[
10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
],
# S4
[
7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
],
# S5
[
2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
],
# S6
[
12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
],
# S7
[
4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
],
# S8
[
13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
]
]

P = [
  16,7,20,21,29,12,28,17,
  1,15,23,26,5,18,31,10,
  2,8,24,14,32,27,3,9,
  19,13,30,6,22,11,4,25
]

PC1 = [
  57,49,41,33,25,17,9,
  1,58,50,42,34,26,18,
  10,2,59,51,43,35,27,
  19,11,3,60,52,44,36,
  63,55,47,39,31,23,15,
  7,62,54,46,38,30,22,
  14,6,61,53,45,37,29,
  21,13,5,28,20,12,4
]

PC2 = [
  14,17,11,24,1,5,
  3,28,15,6,21,10,
  23,19,12,4,26,8,
  16,7,27,20,13,2,
  41,52,31,37,47,55,
  30,40,51,45,33,48,
  44,49,39,56,34,53,
  46,42,50,36,29,32
]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# ---------- Utilities ----------
def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

def int_to_bytes(i: int, length: int) -> bytes:
    return i.to_bytes(length, byteorder='big')

def permute_block_64(in_block: bytes, table: List[int]) -> int:
    block_int = bytes_to_int(in_block)
    out = 0
    for pos in table:
        out = (out << 1) | ((block_int >> (64 - pos)) & 0x1)
    return out

def permute_key_56(key64: bytes) -> int:
    k = bytes_to_int(key64)
    out = 0
    for pos in PC1:
        out = (out << 1) | ((k >> (64 - pos)) & 0x1)
    return out

def permute_pc2(c_and_d_56: int) -> int:
    out = 0
    for pos in PC2:
        out = (out << 1) | ((c_and_d_56 >> (56 - pos)) & 0x1)
    return out

# ---------- Key schedule ----------
def generate_subkeys(key8: bytes) -> List[int]:
    if len(key8) != 8:
        raise ValueError("Key must be 8 bytes")
    perm56 = permute_key_56(key8)
    C = (perm56 >> 28) & ((1 << 28) - 1)
    D = perm56 & ((1 << 28) - 1)
    subkeys = []
    for shift in SHIFTS:
        C = ((C << shift) & ((1 << 28) - 1)) | (C >> (28 - shift))
        D = ((D << shift) & ((1 << 28) - 1)) | (D >> (28 - shift))
        combined = (C << 28) | D
        subk = permute_pc2(combined)
        subkeys.append(subk)
    return subkeys

# ---------- Feistel f function ----------
def feistel_f(R32: int, subkey48: int) -> int:
    expansion = 0
    for pos in E:
        expansion = (expansion << 1) | ((R32 >> (32 - pos)) & 0x1)
    x = expansion ^ subkey48
    out32 = 0
    for i in range(8):
        six = (x >> (42 - 6*i)) & 0x3F
        row = ((six & 0x20) >> 4) | (six & 0x1)
        col = (six >> 1) & 0xF
        s_val = S_BOX[i][row*16 + col]
        out32 = (out32 << 4) | s_val
    permuted = 0
    for pos in P:
        permuted = (permuted << 1) | ((out32 >> (32 - pos)) & 0x1)
    return permuted

# ---------- Block encryption / decryption ----------
def encrypt_block(block8: bytes, subkeys: List[int]) -> bytes:
    if len(block8) != 8:
        raise ValueError("Block must be 8 bytes")
    block_int = bytes_to_int(block8)
    ip = 0
    for pos in IP:
        ip = (ip << 1) | ((block_int >> (64 - pos)) & 0x1)
    L = (ip >> 32) & 0xFFFFFFFF
    R = ip & 0xFFFFFFFF
    for i in range(16):
        newL = R
        f = feistel_f(R, subkeys[i])
        newR = L ^ f
        L, R = newL, newR
    preoutput = (R << 32) | L
    out = 0
    for pos in FP:
        out = (out << 1) | ((preoutput >> (64 - pos)) & 0x1)
    return int_to_bytes(out, 8)

def decrypt_block(block8: bytes, subkeys: List[int]) -> bytes:
    if len(block8) != 8:
        raise ValueError("Block must be 8 bytes")
    block_int = bytes_to_int(block8)
    ip = 0
    for pos in IP:
        ip = (ip << 1) | ((block_int >> (64 - pos)) & 0x1)
    L = (ip >> 32) & 0xFFFFFFFF
    R = ip & 0xFFFFFFFF
    for i in range(16):
        newL = R
        f = feistel_f(R, subkeys[15 - i])
        newR = L ^ f
        L, R = newL, newR
    preoutput = (R << 32) | L
    out = 0
    for pos in FP:
        out = (out << 1) | ((preoutput >> (64 - pos)) & 0x1)
    return int_to_bytes(out, 8)

# ---------- Padding ----------
def pkcs5_pad(data: bytes) -> bytes:
    pad_len = 8 - (len(data) % 8)
    if pad_len == 0:
        pad_len = 8
    return data + bytes([pad_len]) * pad_len

def pkcs5_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Empty on unpad")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

# ---------- CBC mode wrappers ----------
def encrypt_cbc(plaintext: bytes, key8: bytes, iv: bytes = None) -> bytes:
    if iv is None:
        iv = os.urandom(8)
    if len(iv) != 8:
        raise ValueError("IV must be 8 bytes")
    subkeys = generate_subkeys(key8)
    pt = pkcs5_pad(plaintext)
    blocks = [pt[i:i+8] for i in range(0, len(pt), 8)]
    cipher_blocks = []
    prev = iv
    for b in blocks:
        x = bytes(a ^ b for a,b in zip(prev, b))
        ct = encrypt_block(x, subkeys)
        cipher_blocks.append(ct)
        prev = ct
    return iv + b''.join(cipher_blocks)

def decrypt_cbc(ciphertext: bytes, key8: bytes) -> bytes:
    if len(ciphertext) < 8 or len(ciphertext) % 8 != 0:
        raise ValueError("Ciphertext length invalid")
    iv = ciphertext[:8]
    cblocks = [ciphertext[i:i+8] for i in range(8, len(ciphertext), 8)]
    subkeys = generate_subkeys(key8)
    plain_blocks = []
    prev = iv
    for ct in cblocks:
        x = decrypt_block(ct, subkeys)
        p = bytes(a ^ b for a,b in zip(prev, x))
        plain_blocks.append(p)
        prev = ct
    pt_padded = b''.join(plain_blocks)
    return pkcs5_unpad(pt_padded)

# ---------- Self-test ----------
if __name__ == "__main__":
    key = b"12345678"
    msg = b"Hello DES from scratch! This is a test message."
    print("Plaintext:", msg)
    ct = encrypt_cbc(msg, key)
    print("Ciphertext (hex):", ct.hex())
    pt = decrypt_cbc(ct, key)
    print("Decrypted:", pt)
    assert pt == msg
    print("Roundtrip OK.")
