from cryptol.cryptol import *
from BitVector import *

cry = Cryptol("tcp://127.0.0.1", 5555)
rfc5297 = cry.load_module(os.getcwd() + "/rfc5297.md")

# Key : 32 bytes
# ad  : 2D array, N strings of arbitrary length.
# plaintext: a string of no more than 2^71-128 bits.
def sivEncrypt(key,ad,plaintext):
    print "key: " + str(key)
    print "ad: " + str([ str(Si) for Si in ad ])
    print "plaintext: " + str(pt)
    if len(ad) > 0:
        ctx = rfc5297.S2Vinit(key)
        init = ad[:len(ad)-1]
        for Si in ad:
            print "Si = " + str(Si)
            rfc5297.S2Vstep((ctx,Si))
        siv = rfc5297.S2Vfinish((ctx,ad[-1]))
    else:
        siv = rfc5297.S2Vempty(key)
    return sivEncrypt(key,siv,plaintext);


if __name__ == '__main__':
    key = BitVector(hexstring='fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
    ad = [ BitVector(hexstring=s) for s in
           [ '10111213', '14151617', '18191a1b', '1c1d1e1f', '20212223', '24252627' ] ]
    pt = BitVector(hexstring='112233445566778899aabbccddee')
    print str(sivEncrypt(key,ad,pt))
