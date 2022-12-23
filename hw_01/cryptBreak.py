#!/usr/bin/env python3.9

# Homework Header

# Homework Number: 1
# Name: Saumya Navani
# ECN Login: navani
# Due Date: February 3, 2022

#  cryptBreak.py
#  Saumya Navani  (navani@purdue.edu)

# cryptBreak file to recover decrypted code and key from a text file with encrypted text.
# Used code from lecture 2 and modified it, credit for decryption algorithm goes to Professor Avinash Kak.

from BitVector import *  # (A)


def cryptBreak(ciphertextFile, key_bv):
    # Arguments:
    # * ciphertextFile: String containing file name of the ciphertext
    # * key_bv: 16-bit BitVector for the decryption key
    #
    # Function Description:
    # Attempts to decrypt the ciphertext within ciphertextFile file using key_bv and returns
    # the original plaintext as a string

    PassPhrase = "Hopes and dreams of a million years"  # (C)

    BLOCKSIZE = 16
    numbytes = BLOCKSIZE // 8
    limit = pow(2, 16)

    bv_iv = BitVector(bitlist=[0] * BLOCKSIZE)
    for i in range(0, len(PassPhrase) // numbytes):
        textstr = PassPhrase[i * numbytes:(i + 1) * numbytes]
        bv_iv ^= BitVector(textstring=textstr)

    FILEIN = open(ciphertextFile)
    encrypted_bv = BitVector(hexstring=FILEIN.read())

    msg_decrypted_bv = BitVector(size=0)
    previous_decrypted_block = bv_iv
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):
        bv = encrypted_bv[i * BLOCKSIZE:(i + 1) * BLOCKSIZE]
        temp = bv.deep_copy()
        bv ^= previous_decrypted_block
        previous_decrypted_block = temp
        bv ^= key_bv
        msg_decrypted_bv += bv

    outputtext = msg_decrypted_bv.get_text_from_bitvector()

    return outputtext


if __name__ == "__main__":
    for i in range(0, pow(2, 16)):
        tk = chr(i)
        key_bv = BitVector(intVal=i, size=16)
        decryptedMessage = cryptBreak('ciphertext.txt', key_bv)
        if "Douglas Adams" in decryptedMessage:
            print("’Encryption Broken!")
            print("Message: ", decryptedMessage)
            break
        else:
            print("Not decrypted yet")

