# -*- coding: utf-8 -*-

"""An interface to the Cryptol interpreter.


"""

from BitVector import BitVector
from zmq import Context, REQ
import atexit

class Cryptol:
    """A Cryptol interpreter session.

    Instances of this class are sessions with the Cryptol server. The
    main way to use one of these instances is to call :meth:`load_module`
    or :meth:`prelude`.

    """
    def __init__(self, addr, main_port):
        self._loaded_modules = []
        self._ctx = Context()
        self._addr = addr
        self._main_req = self._ctx.socket(REQ)
        self._main_req.connect(self._addr + ':' + str(main_port))
        atexit.register(self.exit)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.exit()
        return None

    def exit(self):
        for mod in self._loaded_modules:
            mod.exit()
            self._main_req.close()
            self._ctx.destroy()

    def load_module(self, filepath):
        self._main_req.send_json({'tag': 'connect'})
        resp = self._main_req.recv_json()
        # print 'response: ' + str(resp)
        worker_port = resp['port']
        req = self._ctx.socket(REQ)
        req.connect(self._addr + ':' + str(worker_port))

        mod = _CryptolModule(self, req, filepath)
        self._loaded_modules.append(mod)
        return mod

    def prelude(self):
        return self.load_module("/Users/acfoltzer/src/cryptol/lib/Cryptol.cry")

class _CryptolModule:

    def __init__(self, cry_ctx, req, filepath):
        self._cry_ctx = cry_ctx
        self._req = req
        self._req.send_json({'tag': 'loadModule', 'filePath': filepath})
        self._req.recv_json()
        self._req.send_json({'tag': 'browse'})
        tlDecls = self._req.recv_json()['decls']['ifDecls']
        for x in tlDecls:
            setattr(self.__class__, x, self.eval(x))


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.exit()
        return None

    def _tag_expr(self, tag, expr):
        self._req.send_json({'tag': tag, 'expr': expr})
        resp = self._req.recv_json()
        return resp

    def _from_value(self, val):
        # VBit
        if 'bit' in val:
            return val['bit']
        # VRecord
        if 'record' in val:
            rec = {}
            for field in val['record']:
                fname = field[0]['Name']
                fval = self._from_value(field[1])
                rec[fname] = fval
            return rec
        # VTuple
        if 'tuple' in val:
            tup = ()
            for tval in val['tuple']:
                tup = tup + (self._from_value(tval),)
            return tup
        # VSeq
        if 'sequence' in val and val['sequence']['isWord']:
            return BitVector(bitlist = [self._from_value(elt) for elt in val['sequence']['elements']])
        if 'sequence' in val and not val['sequence']['isWord']:
            return [self._from_value(elt) for elt in val['sequence']['elements']]
        # VWord
        if 'word' in val:
            bv = val['word']['bitvector']
            v = bv['value']
            w = bv['width']
            # print "value: " + str(v)
            # print "width: " + str(w)
            # print "value % (2**w): " + str(v % (2**w))
            if (w == 0):
                return None
            else:
                return BitVector(intVal = v % (2**w), size = w)
        return val

    def _from_funvalue(self, handle):
        # print "trying to build a closure for " + str(handle)
        def apply(self, arg):
            # print "applying " + str(arg) + " to handle " + str(handle) + " in context " + str(self)
            self._req.send_json({'tag': 'applyFun', 'handle': handle, 'arg': self._to_value(arg)})
            val = self._req.recv_json()
            if val['tag'] == 'value':
                # print "value"
                return self._from_value(val['value'])
            elif val['tag'] == 'funValue':
                # print "funValue"
                return self._from_funvalue(val['handle'])
        return apply

    def _to_value(self, pyval):
        # VBit
        if isinstance(pyval, bool):
            return {'bit': pyval}
        # VRecord
        elif isinstance(pyval, dict):
            return {'record': [[{'Name': k}, self._to_value(v)] for k,v in pyval.items()]}
        # VTuple
        elif isinstance(pyval, tuple):
            return {'tuple': [self._to_value(v) for v in pyval]}
        # VSeq
        elif isinstance(pyval, list):
            # TODO: assert homogeneous, set isWord
            return {'sequence': {'isWord': False, 'elements': [self._to_value(v) for v in pyval]}}
        # VWord
        elif isinstance(pyval, BitVector):
            return {'word': {'bitvector': {'width': pyval.length(), 'value': int(pyval)}}}
        raise ValueError("Unable to convert Python value into Cryptol value: " + str(pyval))

    def eval(self, expr):
        val = self._tag_expr('evalExpr', expr)
        if val['tag'] == 'value':
            # print "value"
            return self._from_value(val['value'])
        elif val['tag'] == 'funValue':
            # print "funValue"
            return self._from_funvalue(val['handle'])

    def typeof(self, expr):
        return self._tag_expr('typeOf', expr)

    def check(self, expr):
        return self._tag_expr('check', expr)

    def exhaust(self, expr):
        return self._tag_expr('exhaust', expr)

    def prove(self, expr):
        return self._tag_expr('prove', expr)

    def sat(self, expr):
        return self._tag_expr('sat', expr)

    def setopt(self, k, v):
        self._req.send_json({'tag': 'setOpt', 'key': k, 'value': v})
        return self._req.recv_json()

    def browse(self):
        self._req.send_json({'tag': 'browse'})
        return self._req.recv_json()

    def exit(self):
        self._cry_ctx._loaded_modules.remove(self)
        self._req.send_json({'tag': 'exit'})
        return self._req.recv_json()


# Takes a JSON representation of a Schema and returns whether or not
# the type is a function.
def is_function(sch):
    ans = False
    try:
        ans = 'TCFun' in sch['sType']['TCon'][0]['TC']
    except (IndexError, KeyError):
        pass
    return ans

if __name__ == '__main__':
    cry = Cryptol("tcp://127.0.0.1", 5555)
    # print cry
    with cry.load_module("/Users/acfoltzer/src/cryptol/lib/Cryptol.cry") as prelude:
        exp = "\\x -> x + 0x4"
        print "*** eval(" + exp + ")"
        fh = prelude.eval(exp)
        print fh
        modules = [prelude]
        modules.append(cry.load_module("/Users/acfoltzer/src/cryptol/docs/ProgrammingCryptol/aes/AES.cry"))
        print modules
        modules.remove(prelude)
        print modules
    # print "*** eval(1+1)"
    # print cry.eval("1+1")
    # print "*** typeof(0xdeadbeef)"

    # print cry.typeof("0xdeadbeef")
    # print "*** check(\\x -> x + 0x00 == x)"
    # print cry.check("\\x -> x + 0x00 == x")
    # print "*** exhaust(\\x -> x + 0x00 == x)"
    # print cry.exhaust("\\x -> x + 0x00 == x")
    # print "*** prove(\\x -> x + 0x00 == x)"
    # print cry.prove("\\x -> x + 0x00 == x")
    # print "*** sat(\\x -> x + 0x00 == x)"
    # print cry.sat("\\x -> x + 0x00 == x")
    # print "*** setopt(prover, z3)"
    # print cry.setopt("prover", "z3")
    # print "*** sat(\\x -> x + 0x00 == x)"
    # print cry.sat("\\x -> x + 0x00 == x")
    # print "*** browse"
    # print cry.browse()
