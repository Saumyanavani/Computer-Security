#!/usr/bin/env python3.9

# Homework Number: 5
# Name: Saumya Navani
# ECN Login: navani
# Due Date: 2/22/2022


from BitVector import *
from Crypto.Cipher import AES


def encrypt(dt_by, key):
    cipher = AES.new(key, AES.MODE_ECB)
    cipher = cipher.encrypt(dt_by)
    return BitVector(rawbytes = cipher)


def ctr_aes_image(iv, image_file='image.ppm', out_file='enc_image.ppm', key_file='key.txt'):
    '''
    * Arguments:
    iv: 128-bit initialization vector
    image_file: input .ppm image file name
    out_file: encrypted .ppm image file name
    key_file: Filename containing encryption key (in ASCII)
    * Function Description:
    This function encrypts image_file using CTR mode AES and writes the encryption
    to out_file. No return value is required.
    '''
    with open(key_file, 'rb') as f:
        key = f.read(32)
    out_f = open(out_file, 'wb')
    img = open(image_file, 'rb')
    hdr = []
    bv = BitVector(filename=image_file)
    for x in range(0, 3):
        hdr.append(img.readline())
    for h in hdr:
        out_f.write(h)
        bv.read_bits_from_file(len(h)*8)
    img.close()
    index = 0
    while bv.more_to_read:
        date_f = bv.read_bits_from_file(128)
        if len(date_f) < 128:
            date_f.pad_from_right(128 - len(date_f))
        if len(date_f) > 0:
            bitvec = BitVector(intVal=int(iv) + index, size=128) # CTR mode AES logic used here
            bv_by = bytes.fromhex(bitvec.get_hex_string_from_bitvector())
            bv_enc = encrypt(bv_by, key)
            date_f ^= bv_enc
            date_f.write_to_file(out_f)
            index += 1
    out_f.close()


if __name__ == "__main__":
    iv = BitVector(textstring='computersecurity') #iv will be 128 bits
    ctr_aes_image(iv,'image.ppm','enc_image.ppm','keyCTR.txt')