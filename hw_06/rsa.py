#!/usr/bin/env python3.9


# Homework Number: 6
# Name: Saumya Navani
# ECN Login: navani
# Due Date: 3/3/2022


from PrimeGenerator import *
from BitVector import *


# The function to calculate gcd using Euclid's Theorem
def euc_gcd(x, y):
    while y:
        x, y = y, x % y
    return x


# Generates the prime number pair for RSA encryption and writes them to two output files
def key_generator(p_file_kg, q_file_kg):
    e = 65537
    # e_bv = BitVector(intVal=e)
    while True:
        gen = PrimeGenerator(bits=128)
        p = gen.findPrime()
        q = gen.findPrime()
        if p != q:
            if (euc_gcd(p - 1, e) == 1) and (euc_gcd(q - 1, e) == 1):
                break

    with open(p_file_kg, 'w') as f:
        f.write(str(p))
    with open(q_file_kg, 'w') as f:
        f.write(str(q))

    # n = p * q
    # totient = (p-1) * (q-1)
    # totient_bv = BitVector(intVal=totient)
    # d_bv = e_bv.multiplicative_inverse(totient_bv)
    # d = d_bv.int_val()
    # pub_key = [e, n]
    # priv_key = [d, n]

    # return pub_key, priv_key  # ask Br?


# Encrypt Function for the output files
def encrypt(message_file_en, p_file_en, q_file_en, out_file_en):
    e = 65537

    with open(p_file_en, 'r') as f:
        p = int(f.read())
    with open(q_file_en, 'r') as f:
        q = int(f.read())

    out_f = open(out_file_en, 'w')
    n = p * q

    bv = BitVector(filename=message_file_en)  # making a bitvector from input message
    while bv.more_to_read:
        bitvec = bv.read_bits_from_file(blocksize=128)
        if len(bitvec) < 128:
            bitvec.pad_from_right(128 % len(bitvec))  # padding from right if block is not 128 bits
        bitvec.pad_from_left(128)  # padding from left with 128 zeros
        c_val = pow(int(bitvec), e, n)
        c_bv = BitVector(intVal=c_val, size=256)
        out_f.write(c_bv.get_bitvector_in_hex())

    out_f.close()


# Chinese Remainder Theorem function for RSA Decrypt
def crt(c, d, p, q, n):
    c = int(c)
    vp = pow(c, d, p)
    vq = pow(c, d, q)
    p_bv = BitVector(intVal=p)
    q_bv = BitVector(intVal=q)
    q_mul = int(q_bv.multiplicative_inverse(p_bv))
    p_mul = int(p_bv.multiplicative_inverse(q_bv))
    xp = q * q_mul
    xq = p * p_mul
    res = ((vp * xp) + (vq * xq)) % n
    return res


# Decrypt function for RSA, takes encrypted file and p and q files as inputs, stores decrypted message in decrypted file
def decrypt(enc_file_de, p_file_de, q_file_de, out_file_de):
    e = 65537
    e_bv = BitVector(intVal=e)  # Bitvector for e value

    # Reading p and q values from files
    with open(p_file_de, 'r') as f:
        p = int(f.read())
    with open(q_file_de, 'r') as f:
        q = int(f.read())

    out_f = open(out_file_de, 'wb')

    # Calculation of n and d values
    n = p * q
    totient = (p - 1) * (q - 1)
    totient_bv = BitVector(intVal=totient)
    d_bv = e_bv.multiplicative_inverse(totient_bv)
    d = d_bv.int_val()
    enc = open(enc_file_de, 'r')
    enc_con = enc.read()
    bitvec = BitVector(hexstring=enc_con)  # Bitvector for encrypted content

    # Cycling through encrypted Bitvector 256 bits at a time
    for i in range(0, len(bitvec), 256):
        bv = bitvec[i:i+256]
        ran = crt(bv, d, p, q, n)
        ran_bv = BitVector(intVal=ran, size=256)
        ran_bv = ran_bv[128:256]  # removing left-padding from encryption
        ran_bv.write_to_file(out_f)

    out_f.close()
    return


if __name__ == '__main__':
    if sys.argv[1] == "-e":
        if len(sys.argv) != 6:
            print("Check arguments for encrypt function")
        else:
            message_file = sys.argv[2]
            p_file = sys.argv[3]
            q_file = sys.argv[4]
            out_file = sys.argv[5]
            encrypt(message_file, p_file, q_file, out_file)
    elif sys.argv[1] == "-d":
        if len(sys.argv) != 6:
            print("Check arguments for decrypt function")
        else:
            enc_file = sys.argv[2]
            p_file = sys.argv[3]
            q_file = sys.argv[4]
            out_file = sys.argv[5]
            decrypt(enc_file, p_file, q_file, out_file)
    elif sys.argv[1] == "-g":
        if len(sys.argv) != 4:
            print("Check arguments for gen_key function")
        else:
            p_file = sys.argv[2]
            q_file = sys.argv[3]
            key_generator(p_file, q_file)
    else:
        print("check command")
        sys.exit()
