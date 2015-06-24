from BitVector import BitVector
from zmq import Context, REQ

class Cryptol:
    ctx = Context()
    main_req = None
    worker_req = None

    def __init__(self, addr, main_port):
        self.main_req = self.ctx.socket(REQ)
        self.main_req.connect(addr + ':' + str(main_port))
        self.main_req.send_json({'tag': 'connect'})
        resp = self.main_req.recv_json()
        print 'response: ' + str(resp)
        worker_port = resp['port']
        self.worker_req = self.ctx.socket(REQ)
        self.worker_req.connect(addr + ':' + str(worker_port))

    def __tag_expr(self, tag, expr):
        self.worker_req.send_json({'tag': tag, 'expr': expr})
        resp = self.worker_req.recv_json()
        print resp
        return resp

    def __from_value(self, val):
        # VBit
        if 'bit' in val:
            return val['bit']
        # VRecord
        if 'record' in val:
            rec = {}
            for field in val['record']:
                fname = field[0]['Name']
                fval = self.__from_value(field[1])
                rec[fname] = fval
            return rec
        # VTuple
        if 'tuple' in val:
            tup = ()
            for tval in val['tuple']:
                tup = tup + (self.__from_value(tval),)
            return tup
        # VSeq
        if 'sequence' in val and val['sequence']['isWord']:
            return BitVector(bitlist = [self.__from_value(elt) for elt in val['sequence']['elements']])
        if 'sequence' in val and not val['sequence']['isWord']:
            return [self.__from_value(elt) for elt in val['sequence']['elements']]
        # VWord
        if 'word' in val:
            bv = val['word']['bitvector']
            v = bv['value']
            w = bv['width']
            return BitVector(intVal = v % (2**w), size = w)
        return val

    def __from_funvalue(self, handle):
        print "trying to build a closure for " + str(handle)
        def apply(arg):
            print "applying " + str(arg) + " to handle " + str(handle) + " in context " + str(self)
            self.worker_req.send_json({'tag': 'applyFun', 'handle': handle, 'arg': self.__to_value(arg)})
            val = self.worker_req.recv_json()
            if val['tag'] == 'value':
                print "value"
                return self.__from_value(val['value'])
            elif val['tag'] == 'funValue':
                print "funValue"
                return self.__from_funvalue(val['handle'])
        return apply

    def __to_value(self, pyval):
        # VBit
        if isinstance(pyval, bool):
            return {'bit': pyval}
        # VRecord
        elif isinstance(pyval, dict):
            return {'record': [[{'Name': k}, self.__to_value(v)] for k,v in pyval.items()]}
        # VTuple
        elif isinstance(pyval, tuple):
            return {'tuple': [self.__to_value(v) for v in pyval]}
        # VSeq
        elif isinstance(pyval, list):
            # TODO: assert homogeneous, set isWord
            return {'sequence': {'isWord': False, 'elements': [self.__to_value(v) for v in pyval]}}
        # VWord
        elif isinstance(pyval, BitVector):
            return {'word': {'bitvector': {'width': pyval.length(), 'value': int(pyval)}}}
        raise ValueError("Unable to convert Python value into Cryptol value")

    def eval(self, expr):
        val = self.__tag_expr('evalExpr', expr)
        if val['tag'] == 'value':
            print "value"
            return self.__from_value(val['value'])
        elif val['tag'] == 'funValue':
            print "funValue"
            return self.__from_funvalue(val['handle'])

    def typeof(self, expr):
        return self.__tag_expr('typeOf', expr)

    def check(self, expr):
        return self.__tag_expr('check', expr)

    def exhaust(self, expr):
        return self.__tag_expr('exhaust', expr)

    def prove(self, expr):
        return self.__tag_expr('prove', expr)

    def sat(self, expr):
        return self.__tag_expr('sat', expr)

    def setopt(self, k, v):
        self.worker_req.send_json({'tag': 'setOpt', 'key': k, 'value': v})
        return self.worker_req.recv_json()

    def load_module(self, filepath):
        self.worker_req.send_json({'tag': 'loadModule', 'filePath': filepath})
        self.worker_req.recv_json()
        self.worker_req.send_json({'tag': 'browse'})
        tlNames = self.worker_req.recv_json()['decls']['ifDecls'].keys()
        print tlNames

    def browse(self):
        self.worker_req.send_json({'tag': 'browse'})
        return self.worker_req.recv_json()

    def exit(self):
        self.worker_req.send_json({'tag': 'exit'})
        return self.worker_req.recv_json()

# Takes a JSON representation of a Schema and returns whether or not
# the type is a function.
def is_function(sch):
    return None

if __name__ == '__main__':
    cry = Cryptol("tcp://127.0.0.1", 5555)
    print cry
    exp = "\\x -> x + 0x4"
    print "*** eval(" + exp + ")"
    fh = cry.eval(exp)
    print fh
    
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
