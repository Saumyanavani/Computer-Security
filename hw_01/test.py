import cryptBreak
from BitVector import *

#someRandomInteger = 9999  # Arbitrary integer for creating a BitVector
#decryptedMessage, decrypted_key = cryptBreak.cryptBreak("ciphertext.txt", key_bv)
for i in range(0, 65536):
    tk = chr(i)
    key_bv = BitVector(intVal=i, size=16)
    decryptedMessage, key = cryptBreak.cryptBreak('ciphertext.txt', key_bv)
    if "Douglas Adams" in decryptedMessage:
        print("’Encryption Broken!")
        key = int(key, 2)
        print("Key: ", key)
        print("Message: ", decryptedMessage)
        break
    else:
        print("Not decrypted yet")
