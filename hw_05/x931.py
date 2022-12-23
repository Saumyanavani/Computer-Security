#!/usr/bin/env python3.9


# Homework Number: 5
# Name: Saumya Navani
# ECN Login: navani
# Due Date: 2/22/2022

import BitVector
from BitVector import *
from Crypto.Cipher import AES


def encrypt(dt_by, key):
    cipher = AES.new(key, AES.MODE_ECB)
    cipher = cipher.encrypt(dt_by)
    return BitVector(rawbytes = cipher)


def x931(v0, dt, totalNum, key_file):
    with open(key_file, 'rb') as f:
        key = f.read(32)

    numbers = []
    dt_by = bytes.fromhex(dt.get_hex_string_from_bitvector())
    dt_enc = encrypt(dt_by, key)
    for i in range(totalNum):
        dt_x = v0 ^ dt_enc
        dt_by2 = bytes.fromhex(dt_x.get_hex_string_from_bitvector())
        dt_enc2 = encrypt(dt_by2, key)
        numbers.append(dt_enc2)

        dt_x2 = dt_enc2 ^ dt_enc
        dt_by3 = bytes.fromhex(dt_x2.get_hex_string_from_bitvector())
        dt_enc3 = encrypt(dt_by3, key)

        v0 = dt_enc3
    return numbers


if __name__ == "__main__":
    v0 = BitVector(textstring="computersecurity") #v0 will be  128 bits
    #As mentioned before, for testing purposes dt is set to a predetermined value
    dt = BitVector(intVal = 501, size=128)
    listX931 = x931(v0,dt,3,"keyX931.txt")
    #Check if list is correct
    print("{}\n{}\n{}".format(int(listX931[0]),int(listX931[1]),int(listX931[2])))
