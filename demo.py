from cryptol.cryptol import *
from BitVector import *

cry = Cryptol('tcp://127.0.0.1', 5555)

prelude_cry_file = '/Users/acfoltzer/src/cryptol/lib/Cryptol.cry'
prelude = cry.load_module(prelude_cry_file)

aes_cry_file = '/Users/acfoltzer/src/cryptol/docs/ProgrammingCryptol/aes/AES.cry'
aes = cry.load_module(aes_cry_file)

if __name__ == '__main__':    
    key = BitVector(intVal = 0x2b7e151628aed2a6abf7158809cf4f3c, size = 128)
    pts = [ BitVector(intVal = pt, size = 128) for pt in
              [ 0x6bc1bee22e409f96e93d7e117393172a,
                0xae2d8a571e03ac9c9eb76fac45af8e51,
                0x30c81c46a35ce411e5fbc1191a0a52ef,
                0xf69f2445df4f9b17ad2b417be66c3710 ] ]
    print "key = " + key.get_bitvector_in_hex()
    for pt in pts:
        ct = aes.aesEncrypt((pt, key))
        print "pt = " + pt.get_bitvector_in_hex()
        print "ct = " + ct.get_bitvector_in_hex()
