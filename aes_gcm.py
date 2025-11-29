

import os
from typing import Tuple

# ---------------------------
# AES-128 (encrypt only)
# ---------------------------
SBOX = [
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

RCON = [
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
]

def sub_bytes(state):
    return [SBOX[b] for b in state]

def shift_rows(s):
    return [
        s[0], s[5], s[10], s[15],
        s[4], s[9], s[14], s[3],
        s[8], s[13], s[2], s[7],
        s[12], s[1], s[6], s[11]
    ]

def xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)

def mul(a, b):
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return res

def mix_columns(s):
    out = []
    for i in range(0, 16, 4):
        a = s[i:i+4]
        out += [
            mul(a[0],2) ^ mul(a[1],3) ^ a[2] ^ a[3],
            a[0] ^ mul(a[1],2) ^ mul(a[2],3) ^ a[3],
            a[0] ^ a[1] ^ mul(a[2],2) ^ mul(a[3],3),
            mul(a[0],3) ^ a[1] ^ a[2] ^ mul(a[3],2)
        ]
    return out

def add_round_key(state, round_key):
    return [s ^ k for s, k in zip(state, round_key)]

def key_expansion(key: bytes) -> list:
    assert len(key) == 16
    key_symbols = list(key)
    expanded = key_symbols[:]
    for i in range(4, 44):
        temp = expanded[(i-1)*4 : i*4]
        if i % 4 == 0:
            # rotate
            temp = temp[1:] + temp[:1]
            # apply sbox
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[i//4]
        word = [a ^ b for a, b in zip(expanded[(i-4)*4 : (i-3)*4], temp)]
        expanded.extend(word)
    return expanded  # 176 bytes (11 round keys * 16 bytes)

def aes_encrypt_block(block: bytes, key: bytes) -> bytes:
    """Encrypt single 16-byte block with AES-128 (pure python)."""
    assert len(block) == 16 and len(key) == 16
    state = list(block)
    round_keys = key_expansion(key)
    state = add_round_key(state, round_keys[0:16])
    for r in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[r*16:(r+1)*16])
    # final round
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[160:176])
    return bytes(state)

# ---------------------------
# GCM: GHASH (GF(2^128) carryless multiply)
# ---------------------------

# Reduction polynomial constant for GCM: x^128 + x^7 + x^2 + x + 1
# Represented as 0xE1 << 120 (i.e. 0xE100...0 with 120 zeros)
RED_POLY = 0xE1000000000000000000000000000000

def bytes_to_int(be: bytes) -> int:
    return int.from_bytes(be, byteorder='big')

def int_to_bytes(i: int, length: int=16) -> bytes:
    return i.to_bytes(length, byteorder='big')

def gf_mul(x: int, y: int) -> int:
    """
    Carry-less multiply x and y (both 128-bit integers) in GF(2).
    Returns a 128-bit integer reduced modulo the GCM polynomial.
    """
    # naive carry-less multiplication -> 256-bit intermediate
    z = 0
    xt = x
    yt = y
    # multiply (carry-less): loop over bits of y
    while yt:
        if yt & 1:
            z ^= xt
        yt >>= 1
        xt <<= 1
    # now reduce z (<= 256 bits) modulo the polynomial
    # Reduce while z has degree >= 128
    # RED_POLY corresponds to x^128 + x^7 + x^2 + x + 1
    for shift in range(z.bit_length() - 129, -1, -1):
        if shift < 0:
            break
        if (z >> (shift + 128)) & 1:
            z ^= RED_POLY << shift
    return z & ((1 << 128) - 1)

def ghash(H: bytes, aad: bytes, cipher: bytes) -> bytes:
    """
    GHASH(H, A, C) per GCM spec:
    Y_0 = 0
    Y_i = (Y_{i-1} xor X_i) * H    (carry-less multiply)
    where X_i are 128-bit blocks from A||pad||C||pad||len(A)||len(C)
    """
    H_int = bytes_to_int(H)
    Y = 0
    # process associated data A
    def process_blocks(data: bytes, Y: int) -> int:
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            if len(block) < 16:
                block = block + b'\x00' * (16 - len(block))
            X = bytes_to_int(block)
            Y = gf_mul(Y ^ X, H_int)
        return Y

    Y = process_blocks(aad, Y)
    Y = process_blocks(cipher, Y)
    # lengths block: 64-bit len(A)*8 || 64-bit len(C)*8
    a_len_bits = (len(aad) * 8) & ((1 << 64) - 1)
    c_len_bits = (len(cipher) * 8) & ((1 << 64) - 1)
    len_block = (a_len_bits << 64) | c_len_bits
    Y = gf_mul(Y ^ len_block, H_int)
    return int_to_bytes(Y, 16)

# ---------------------------
# CTR helpers
# ---------------------------
def inc32(counter_block: bytes) -> bytes:
    """Increment last 32 bits (big endian) modulo 2^32."""
    assert len(counter_block) == 16
    prefix = counter_block[:12]
    ctr = int.from_bytes(counter_block[12:], 'big')
    ctr = (ctr + 1) & 0xFFFFFFFF
    return prefix + ctr.to_bytes(4, 'big')

def build_J0(iv: bytes, H: bytes) -> bytes:
    """
    Build initial counter block J0:
    - if len(iv) == 12 bytes: J0 = iv || 0x00000001
    - else: J0 = GHASH(H, A="", C=iv padded) per spec
    """
    if len(iv) == 12:
        return iv + b'\x00\x00\x00\x01'
    else:
        # J0 = GHASH(H, "", IV || padding || [len(IV in bits)])
        # i.e., GHASH over iv as 'cipher' parameter with empty AAD
        # GHASH will already do the padding and length block
        return ghash(H, b'', iv)

# ---------------------------
# GCM Encrypt / Decrypt
# ---------------------------
def aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes=b'') -> Tuple[bytes, bytes]:
    """
    Returns (ciphertext, tag)
    """
    assert len(key) == 16
    # 1) H = AES_K(0^128)
    H = aes_encrypt_block(b'\x00' * 16, key)

    # 2) J0
    J0 = build_J0(iv, H)

    # 3) CTR mode: generate keystream blocks
    ciphertext = bytearray()
    # counter block first is inc32(J0) before encrypting (spec uses incremented J0)
    counter = J0
    block_count = 0
    for i in range(0, len(plaintext), 16):
        counter = inc32(counter)
        keystream = aes_encrypt_block(counter, key)
        block = plaintext[i:i+16]
        # XOR
        ct_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
        ciphertext.extend(ct_block)
        block_count += 1

    C = bytes(ciphertext)
    # 4) compute tag: T = AES_K(J0) XOR GHASH(H, A, C)
    S = aes_encrypt_block(J0, key)
    g = ghash(H, aad, C)
    T = bytes(a ^ b for a, b in zip(S, g))
    return C, T

def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, aad: bytes=b'', tag: bytes=b'') -> Tuple[bytes, bool]:
    """
    Returns (plaintext, is_tag_valid)
    """
    assert len(key) == 16
    H = aes_encrypt_block(b'\x00' * 16, key)
    J0 = build_J0(iv, H)

    # compute expected tag
    S = aes_encrypt_block(J0, key)
    g = ghash(H, aad, ciphertext)
    expected_tag = bytes(a ^ b for a, b in zip(S, g))

    # constant-time compare (simple)
    if len(tag) != 16:
        return b'', False
    tag_valid = (bytes(x ^ y for x, y in zip(tag, expected_tag)).count(0) == 16)

    # if tag invalid, still produce plaintext per spec? Here we'll decrypt and return tag flag.
    plaintext = bytearray()
    counter = J0
    for i in range(0, len(ciphertext), 16):
        counter = inc32(counter)
        keystream = aes_encrypt_block(counter, key)
        block = ciphertext[i:i+16]
        pt_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
        plaintext.extend(pt_block)

    return bytes(plaintext), tag_valid

# ---------------------------
# Utilities / Demo
# ---------------------------
def generate_key() -> bytes:
    return os.urandom(16)

def generate_iv(nbytes: int = 12) -> bytes:
    return os.urandom(nbytes)

if __name__ == "__main__":
    # Demo
    key = generate_key()
    iv = generate_iv(12)   # 12-byte recommended IV
    aad = b"header-authenticated"
    plaintext = b"Secret message for AES-GCM."

    print("Key:", key.hex())
    print("IV :", iv.hex())
    print("AAD:", aad)
    print("Plaintext:", plaintext)

    ct, tag = aes_gcm_encrypt(key, iv, plaintext, aad)
    print("\nCiphertext (hex):", ct.hex())
    print("Tag (hex):       ", tag.hex())

    recovered, ok = aes_gcm_decrypt(key, iv, ct, aad, tag)
    print("\nTag valid:", ok)
    print("Recovered:", recovered)
    if ok:
        print("Recovered text:", recovered.decode())
    else:
        print("Warning: tag verification failed.")
