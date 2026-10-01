#!/usr/bin/env python3
"""
Implementation of Ascon v1.2, an authenticated cipher and hash function.
Identical implementation used on both ESP32 edge node and Kali Linux Secure Gateway.
"""

debug = False
debugpermutation = False

# === Ascon AEAD encryption and decryption ===

def ascon_encrypt(key, nonce, associateddata, plaintext, variant="Ascon-128"):
    assert variant in ["Ascon-128", "Ascon-128a", "Ascon-80pq"]
    assert (len(nonce) == 16 and (len(key) == 16 or (len(key) == 20 and variant == "Ascon-80pq")))
    S = [0, 0, 0, 0, 0]
    k = len(key) * 8
    a = 12
    b = 8 if variant == "Ascon-128a" else 6
    rate = 16 if variant == "Ascon-128a" else 8

    ascon_initialize(S, k, rate, a, b, key, nonce)
    ascon_process_associated_data(S, b, rate, associateddata)
    ciphertext = ascon_process_plaintext(S, b, rate, plaintext)
    tag = ascon_finalize(S, rate, a, key)
    return ciphertext + tag

def ascon_decrypt(key, nonce, associateddata, ciphertext, variant="Ascon-128"):
    assert variant in ["Ascon-128", "Ascon-128a", "Ascon-80pq"]
    assert (len(nonce) == 16 and (len(key) == 16 or (len(key) == 20 and variant == "Ascon-80pq")))
    assert (len(ciphertext) >= 16)
    S = [0, 0, 0, 0, 0]
    k = len(key) * 8
    a = 12
    b = 8 if variant == "Ascon-128a" else 6
    rate = 16 if variant == "Ascon-128a" else 8

    ascon_initialize(S, k, rate, a, b, key, nonce)
    ascon_process_associated_data(S, b, rate, associateddata)
    plaintext = ascon_process_ciphertext(S, b, rate, ciphertext[:-16])
    tag = ascon_finalize(S, rate, a, key)
    if tag == ciphertext[-16:]:
        return plaintext
    else:
        return None

# === Ascon AEAD building blocks ===

def ascon_initialize(S, k, rate, a, b, key, nonce):
    iv_zero_key_nonce = to_bytes([k, rate * 8, a, b] + (20 - len(key)) * [0]) + key + nonce
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(iv_zero_key_nonce)
    ascon_permutation(S, a)
    zero_key = bytes_to_state(zero_bytes(40 - len(key)) + key)
    S[0] ^= zero_key[0]
    S[1] ^= zero_key[1]
    S[2] ^= zero_key[2]
    S[3] ^= zero_key[3]
    S[4] ^= zero_key[4]

def ascon_process_associated_data(S, b, rate, associateddata):
    if len(associateddata) > 0:
        a_zeros = rate - (len(associateddata) % rate) - 1
        a_padding = to_bytes([0x80] + [0 for i in range(a_zeros)])
        a_padded = associateddata + a_padding
        for block in range(0, len(a_padded), rate):
            S[0] ^= bytes_to_int(a_padded[block:block + 8])
            if rate == 16:
                S[1] ^= bytes_to_int(a_padded[block + 8:block + 16])
            ascon_permutation(S, b)
    S[4] ^= 1

def ascon_process_plaintext(S, b, rate, plaintext):
    p_lastlen = len(plaintext) % rate
    p_padding = to_bytes([0x80] + (rate - p_lastlen - 1) * [0x00])
    p_padded = plaintext + p_padding
    ciphertext = to_bytes([])
    for block in range(0, len(p_padded) - rate, rate):
        if rate == 8:
            S[0] ^= bytes_to_int(p_padded[block:block + 8])
            ciphertext += int_to_bytes(S[0], 8)
        elif rate == 16:
            S[0] ^= bytes_to_int(p_padded[block:block + 8])
            S[1] ^= bytes_to_int(p_padded[block + 8:block + 16])
            ciphertext += (int_to_bytes(S[0], 8) + int_to_bytes(S[1], 8))
        ascon_permutation(S, b)
    block = len(p_padded) - rate
    if rate == 8:
        S[0] ^= bytes_to_int(p_padded[block:block + 8])
        ciphertext += int_to_bytes(S[0], 8)[:p_lastlen]
    elif rate == 16:
        S[0] ^= bytes_to_int(p_padded[block:block + 8])
        S[1] ^= bytes_to_int(p_padded[block + 8:block + 16])
        ciphertext += (int_to_bytes(S[0], 8)[:min(8, p_lastlen)] + int_to_bytes(S[1], 8)[:max(0, p_lastlen - 8)])
    return ciphertext

def ascon_process_ciphertext(S, b, rate, ciphertext):
    c_lastlen = len(ciphertext) % rate
    c_padded = ciphertext + zero_bytes(rate - c_lastlen)
    plaintext = to_bytes([])
    for block in range(0, len(c_padded) - rate, rate):
        if rate == 8:
            Ci = bytes_to_int(c_padded[block:block + 8])
            plaintext += int_to_bytes(S[0] ^ Ci, 8)
            S[0] = Ci
        elif rate == 16:
            Ci = (bytes_to_int(c_padded[block:block + 8]), bytes_to_int(c_padded[block + 8:block + 16]))
            plaintext += (int_to_bytes(S[0] ^ Ci[0], 8) + int_to_bytes(S[1] ^ Ci[1], 8))
            S[0] = Ci[0]
            S[1] = Ci[1]
        ascon_permutation(S, b)
    block = len(c_padded) - rate
    if rate == 8:
        c_padding1 = (0x80 << (rate - c_lastlen - 1) * 8)
        c_mask = (0xFFFFFFFFFFFFFFFF >> (c_lastlen * 8))
        Ci = bytes_to_int(c_padded[block:block + 8])
        plaintext += int_to_bytes(Ci ^ S[0], 8)[:c_lastlen]
        S[0] = Ci ^ (S[0] & c_mask) ^ c_padding1
    elif rate == 16:
        c_lastlen_word = c_lastlen % 8
        c_padding1 = (0x80 << (8 - c_lastlen_word - 1) * 8)
        c_mask = (0xFFFFFFFFFFFFFFFF >> (c_lastlen_word * 8))
        Ci = (bytes_to_int(c_padded[block:block + 8]), bytes_to_int(c_padded[block + 8:block + 16]))
        plaintext += (int_to_bytes(S[0] ^ Ci[0], 8) + int_to_bytes(S[1] ^ Ci[1], 8))[:c_lastlen]
        if c_lastlen < 8:
            S[0] = Ci[0] ^ (S[0] & c_mask) ^ c_padding1
        else:
            S[0] = Ci[0]
            S[1] = Ci[1] ^ (S[1] & c_mask) ^ c_padding1
    return plaintext

def ascon_finalize(S, rate, a, key):
    S[rate // 8 + 0] ^= bytes_to_int(key[0:8])
    S[rate // 8 + 1] ^= bytes_to_int(key[8:16])
    S[rate // 8 + 2] ^= bytes_to_int(key[16:])
    ascon_permutation(S, a)
    S[3] ^= bytes_to_int(key[-16:-8])
    S[4] ^= bytes_to_int(key[-8:])
    tag = int_to_bytes(S[3], 8) + int_to_bytes(S[4], 8)
    return tag

def ascon_permutation(S, rounds=1):
    for r in range(12 - rounds, 12):
        S[2] ^= (0xf0 - r * 0x10 + r * 0x1)
        S[0] ^= S[4]
        S[4] ^= S[3]
        S[2] ^= S[1]
        T = [(S[i] ^ 0xFFFFFFFFFFFFFFFF) & S[(i + 1) % 5] for i in range(5)]
        for i in range(5):
            S[i] ^= T[(i + 1) % 5]
        S[1] ^= S[0]
        S[0] ^= S[4]
        S[3] ^= S[2]
        S[2] ^= 0xFFFFFFFFFFFFFFFF
        S[0] ^= rotr(S[0], 19) ^ rotr(S[0], 28)
        S[1] ^= rotr(S[1], 61) ^ rotr(S[1], 39)
        S[2] ^= rotr(S[2], 1) ^ rotr(S[2], 6)
        S[3] ^= rotr(S[3], 10) ^ rotr(S[3], 17)
        S[4] ^= rotr(S[4], 7) ^ rotr(S[4], 41)

def get_random_bytes(num):
    import os
    return to_bytes(os.urandom(num))

def zero_bytes(n):
    return n * b"\x00"

def to_bytes(l):
    return bytes(bytearray(l))

def bytes_to_int(bytes):
    return sum([bi << ((len(bytes) - 1 - i) * 8) for i, bi in enumerate(to_bytes(bytes))])

def bytes_to_state(bytes):
    return [bytes_to_int(bytes[8 * w:8 * (w + 1)]) for w in range(5)]

def int_to_bytes(integer, nbytes):
    return to_bytes([(integer >> ((nbytes - 1 - i) * 8)) % 256 for i in range(nbytes)])

def rotr(val, r):
    return (val >> r) | ((val & (1 << r) - 1) << (64 - r))
