"""CRC32 Synthesis Example

This uses iterative ``sat`` and ``prove`` commands to derive an
implementation of CRC32 given a set of possible instructions defined
in ``CRC32.cry``. This example shows the flexibility gained when using
Python control structures to drive Cryptol sessions, as Cryptol's
domain-specific control flow constructs and type system makes it
difficult to directly express this sort of conditional iteration.

See the paper `Oracle-Guided Component-Based Program Synthesis
<http://www.eecs.berkeley.edu/~sseshia/pubs/b2hd-jha-icse10.html>`_
for more detail on the general approach.

"""

from BitVector import BitVector
import cryptol
import os

crc32 = cryptol.Cryptol().load_module(os.path.abspath('CRC32.cry'))

def sat_step(tests):
    """Find a program that agrees with the oracle for the given tests"""
    prop = ('\\program -> '
            'compute_program(program:[26][lginsn], '
            'CRC32_oracle, [CRC32_to_state(test) | test <- %s ])'
            % crc32.to_expr(tests))
    res = crc32.sat(prop, prover=cryptol.Provers.ABC)
    if len(res) > 0:
        return res[0][0]
    else:
        return None

def prove_step(program):
    """Try to prove the program is correct; give a counterexample otherwise"""
    prop = ('\\a -> '
            'program_is_correct(%s, CRC32_oracle, CRC32_to_state(a))'
            % crc32.to_expr(program))
    res = crc32.prove(prop, prover=cryptol.Provers.Z3)
    if res is not None:
        # project out first and only argument
        return res[0]
    else:
        return None

def main_loop():
    tests = [BitVector(intVal=0, size=32)]
    while True:
        print 'Trying with tests: %s' % crc32.to_expr(tests)
        # Find a candidate program
        pgm = sat_step(tests)
        if pgm is None:
            # Unsat means no program of this length is possible
            print 'Could not find the program'
            break
        # Try out the candidate
        cex = prove_step(pgm)
        if cex is None:
            # No counterexample means the program is correct
            print 'Found the program!'
            pp_program = crc32.eval('printProgram %s' % crc32.to_expr(program))
            for inst in pp_program:
                print ''.join([chr(int(x)) for x in inst])
            break
        else:
            # Add the counterexample to the list of tests and repeat
            print 'Found new counterexample: %s' % crc32.to_expr(cex)
            tests.append(cex)

if __name__ == '__main__':
    main_loop()
