#!/usr/bin/env python3.9


# Homework Number: 6
# Name: Saumya Navani
# ECN Login: navani
# Due Date: 3/3/2022


from BitVector import *
from PrimeGenerator import *
from solve_pRoot_BST import *


# The function to calculate gcd using Euclid's Theorem
def euc_gcd(x, y):
    while y:
        x, y = y, x % y
    return x


# Generates the public and private key pair for RSA encryption
def key_generator():
    e = 3
    e_bv = BitVector(intVal=e)  # Bitvector for the small e value
    while True:
        gen = PrimeGenerator(bits=128)  # generator for the two prime numbers
        p = gen.findPrime()
        q = gen.findPrime()
        # Condition Check
        if p != q:
            if (euc_gcd(p - 1, e) == 1) and (euc_gcd(q - 1, e) == 1):
                break

    # with open(p_file_kg, 'w') as f:
    #     f.write(str(p))
    # with open(q_file_kg, 'w') as f:
    #     f.write(str(q))

    # Calculation for the totient and the public/private keys
    n = p * q
    totient = (p - 1) * (q - 1)
    totient_bv = BitVector(intVal=totient)
    d_bv = e_bv.multiplicative_inverse(totient_bv)
    d = d_bv.int_val()
    pub_key = [e, n]
    priv_key = [d, n]

    return pub_key, priv_key


# Encrypt Function for three output files
def encrypt(message_en, enc1_en, enc2_en, enc3_en, n_1_2_3_en):
    e = 3

    out_f1 = open(enc1_en, 'w')
    out_f2 = open(enc2_en, 'w')
    out_f3 = open(enc3_en, 'w')
    out_f4 = open(n_1_2_3_en, 'w')
    pub, priv = key_generator()
    n = pub[1]
    bv = BitVector(filename=message_en)
    while bv.more_to_read:
        bitvec = bv.read_bits_from_file(blocksize=128)
        if len(bitvec) < 128:
            bitvec.pad_from_right(128 % len(bitvec))  # padding from right if block is less than 128 bits
        bitvec.pad_from_left(128)  # Padding from left with 128 zeros
        c_val = pow(int(bitvec), e, n)  # calculating current encrypted block
        c_bv = BitVector(intVal=c_val, size=256)
        out_f1.write(c_bv.get_bitvector_in_hex())
    out_f4.write(str(n))
    out_f4.write("\n")
    out_f1.close()

    # Second encryption
    # n = key_generator()
    pub, priv = key_generator()
    n = pub[1]
    bv = BitVector(filename=message_en)
    while bv.more_to_read:
        bitvec = bv.read_bits_from_file(blocksize=128)
        if len(bitvec) < 128:
            bitvec.pad_from_right(128 % len(bitvec))
        bitvec.pad_from_left(128)
        c_val = pow(int(bitvec), e, n)
        c_bv = BitVector(intVal=c_val, size=256)
        out_f2.write(c_bv.get_bitvector_in_hex())
    out_f4.write(str(n))
    out_f4.write("\n")
    out_f2.close()

    # Third Encryption
    pub, priv = key_generator()
    n = pub[1]
    bv = BitVector(filename=message_en)
    while bv.more_to_read:
        bitvec = bv.read_bits_from_file(blocksize=128)
        if len(bitvec) < 128:
            bitvec.pad_from_right(128 % len(bitvec))
        bitvec.pad_from_left(128)
        c_val = pow(int(bitvec), e, n)
        c_bv = BitVector(intVal=c_val, size=256)
        out_f3.write(c_bv.get_bitvector_in_hex())
    out_f4.write(str(n))
    out_f4.write("\n")
    out_f3.close()
    out_f4.close()

    return


# Modified CRT function for RSA cracking with three encrypted files.
# Takes three bitvectors and the n values as inputs, returns the result of CRT calculations
def crt(c1, c2, c3, n_values):
    N = n_values[0] * n_values[1] * n_values[2]
    m1 = n_values[1] * n_values[2]
    m2 = n_values[0] * n_values[2]
    m3 = n_values[0] * n_values[1]
    m1_bv = BitVector(intVal=m1)
    m2_bv = BitVector(intVal=m2)
    m3_bv = BitVector(intVal=m3)
    n1_bv = BitVector(intVal=n_values[0])
    n2_bv = BitVector(intVal=n_values[1])
    n3_bv = BitVector(intVal=n_values[2])
    mi_1 = (m1_bv.multiplicative_inverse(n1_bv)).int_val()
    mi_2 = (m2_bv.multiplicative_inverse(n2_bv)).int_val()
    mi_3 = (m3_bv.multiplicative_inverse(n3_bv)).int_val()
    a1 = mi_1 * m1
    a2 = mi_2 * m2
    a3 = mi_3 * m3
    res = ((a1 * int(c1)) + (a2 * int(c2)) + (a3 * int(c3)))
    return res


# RSA Cracking function
def rsa_crack(enc1_cr, enc2_cr, enc3_cr, n_1_2_3_cr, cracked_cr):
    e = 3
    e_bv = BitVector(intVal=e)

    with open(enc1_cr, 'r') as f:
        enc1 = f.read()
    with open(enc2_cr, 'r') as f:
        enc2 = f.read()
    with open(enc3_cr, 'r') as f:
        enc3 = f.read()
    # print(enc3)
    n_values = []
    with open(n_1_2_3_cr, 'r') as f:
        for i in range(3):
            x = f.readline().strip()
            n_values.append(int(x))
    # print("Here")
    # print(n_values)

    # Making three Bitvectors out of the encrypted input files
    enc_1_bv = BitVector(hexstring=enc1)
    enc_2_bv = BitVector(hexstring=enc2)
    enc_3_bv = BitVector(hexstring=enc3)
    out_f = open(cracked_cr, 'wb')
    # n = p * q
    # totient = (p - 1) * (q - 1)
    # totient_bv = BitVector(intVal=totient)
    # d_bv = e_bv.multiplicative_inverse(totient_bv)
    # d = d_bv.int_val()
    N = n_values[0] * n_values[1] * n_values[2]
    for i in range(0, len(enc_1_bv), 256):
        bv_enc1 = enc_1_bv[i:i + 256]
        bv_enc2 = enc_2_bv[i:i + 256]
        bv_enc3 = enc_3_bv[i:i + 256]
        ran = crt(bv_enc1, bv_enc2, bv_enc3, n_values)
        ran = ran % N
        ran_cr = solve_pRoot(3, ran)  # Calculating cube root using solve_pRoot with solve_pRoot_BST
        ran_bv = BitVector(intVal=ran_cr, size=256)
        ran_bv = ran_bv[128:256]  # Getting last 128 bits from the Bitvector/getting rid of encryption padding
        ran_bv.write_to_file(out_f)
        # rint(ran_bv.get_bitvector_in_ascii())
    out_f.close()
    return


if __name__ == '__main__':
    if sys.argv[1] == "-e":
        if len(sys.argv) != 7:
            print("Check arguments for encrypt function")
        else:
            message_file = sys.argv[2]
            enc1_file = sys.argv[3]
            enc2_file = sys.argv[4]
            enc3_file = sys.argv[5]
            n_1_2_3_file = sys.argv[6]
            encrypt(message_file, enc1_file, enc2_file, enc3_file, n_1_2_3_file)
    elif sys.argv[1] == "-c":
        if len(sys.argv) != 7:
            print("Check arguments for crack function")
        else:
            enc1_file = sys.argv[2]
            enc2_file = sys.argv[3]
            enc3_file = sys.argv[4]
            n_1_2_3_file = sys.argv[5]
            crack_file = sys.argv[6]
            rsa_crack(enc1_file, enc2_file, enc3_file, n_1_2_3_file, crack_file)
    else:
        print("check command")
        sys.exit()
