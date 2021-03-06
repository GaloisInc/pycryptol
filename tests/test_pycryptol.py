# -*- coding: utf-8 -*-
# pylint: disable=redefined-outer-name,missing-docstring,
# pylint: disable=wildcard-import,unused-wildcard-import

from cryptol import *
from BitVector import BitVector
from multiprocessing import Process, Lock
import os
import pytest
import signal
import time

@pytest.fixture(scope="module")
def cry(request):
    cry = Cryptol()
    request.addfinalizer(cry.exit)
    return cry

@pytest.fixture(scope="module")
def prelude(cry):
    return cry.prelude()

def test_prelude(prelude):
    assert int(prelude.eval('1+1')) == 0

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

def test_interrupt(cry):
    m = cry.load_module('tests/inf.cry')
    lock = Lock()
    pid = os.getpid()
    lock.acquire()
    def interrupter():
        lock.acquire()
        time.sleep(1)
        # sends SIGINT to main thread
        os.kill(pid, signal.SIGINT)
    child = Process(target=interrupter)
    child.start()
    with pytest.raises(KeyboardInterrupt):
        lock.release()
        m.eval('bot ()')
    assert int(m.eval('1+1')) == 0

def test_check(prelude):
    report = prelude.check('\\x -> (x : [4]) == x')
    assert(report.passed())
    assert(report.is_exhaustive())

    report = prelude.check('\\x -> (x : [8]) == x')
    assert(report.passed())
    assert(not report.is_exhaustive())
    assert(report.coverage() == 0.390625)

    report = prelude.check('\\x -> (x : [8]) == x', limit=256)
    print report.tests_run()
    print report.tests_possible()
    assert(report.passed())
    assert(report.is_exhaustive())
    assert(report.coverage() == 1.0)

    report = prelude.check('\\x -> (x : [8]) == x', limit=None)
    assert(report.passed())
    assert(report.is_exhaustive())
    assert(report.coverage() == 1.0)

    report = prelude.check('\\x -> x != 0x5')
    assert(not report.passed())
    assert(int(report.get_counterexample()[0]) == 5)

    report = prelude.check('\\x -> x != 0xdeadbeefcafe')
    assert(report.passed()) # probabilistic!
    assert(not report.is_exhaustive())
    assert(report.coverage() < 0.1)

    report = prelude.check('\\x -> x + 0x4 == error \"foo\"')
    assert(not report.passed())
    assert(report.has_error())
    assert('foo' in report.get_error())
