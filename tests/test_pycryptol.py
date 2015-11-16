# -*- coding: utf-8 -*-
# pylint: disable=redefined-outer-name,missing-docstring,
# pylint: disable=wildcard-import,unused-wildcard-import

from cryptol import *
from BitVector import BitVector
import pytest

@pytest.fixture(scope="module")
def cry():
    return Cryptol()

@pytest.fixture(scope="module")
def prelude(cry):
    return cry.prelude()

def test_prelude(prelude):
    prelude.eval('1+1')

def test_aes(cry):
    key = BitVector(intVal=0x2b7e151628aed2a6abf7158809cf4f3c, size=128)
    tvs = [(BitVector(intVal=pt, size=128),
            BitVector(intVal=ct, size=128))
           for pt, ct in
           [(0x6bc1bee22e409f96e93d7e117393172a,
             0x3ad77bb40d7a3660a89ecaf32466ef97),
            (0xae2d8a571e03ac9c9eb76fac45af8e51,
             0xf5d3d58503b9699de785895a96fdbaaf),
            (0x30c81c46a35ce411e5fbc1191a0a52ef,
             0x43b1cd7f598ece23881b00e3ed030688),
            (0xf69f2445df4f9b17ad2b417be66c3710,
             0x7b0c785e27e8ad3f8223207104725dd4)]]
    aes = cry.load_module('tests/AES.cry')
    for pt, ct in tvs:
        ct_actual = aes.aesEncrypt((pt, key))
        assert ct == ct_actual

def test_oplus(cry):
    m = cry.load_module('tests/idents.cry')
    oplus = m.decl(u'⊕')
    two = BitVector(intVal=2, size=4)
    three = BitVector(intVal=3, size=4)
    assert int(oplus(two)(three)) == 5
