from BitVector import BitVector
from zmq import Context, REQ

class Cryptol:
    ctx = Context()
    req = None

    def __init__(self, addr):
        self.req = self.ctx.socket(REQ)
        self.req.connect(addr)

    def __tag_expr(self, tag, expr):
        self.req.send_json({'tag': tag, 'expr': expr})
        resp = self.req.recv_json()
        print resp
        return resp

    def __from_value(self, val):
        # VBit
        if isinstance(val, bool):
            return val
        # VRecord
        if val['tag'] == 'record':
            rec = {}
            for field in val['fields']:
                fname = field[0]['contents']
                fval = self.__from_value(field[1])
                rec[fname] = fval
            return rec
        # VTuple
        if val['tag'] == 'tuple':
            tup = ()
            for tval in val['values']:
                tup = tup + (self.__from_value(tval),)
            return tup
        # VSeq
        if val['tag'] == 'sequence' and val['isWord']:
            return BitVector(bitlist = val['elements'])
        if val['tag'] == 'sequence' and not val['isWord']:
            return [self.__from_value(elt) for elt in val['elements']]
        # VWord
        if val['tag'] == 'bitvector':
            return BitVector(intVal = val['value'], size = val['width'])
        return val

    def __from_funvalue(self, handle):
        print "trying to build a closure for " + str(handle)
        def apply(arg):
            print "applying " + str(arg) + " to handle " + str(handle) + " in context " + str(self)
            self.req.send_json({'tag': 'applyFun', 'handle': handle, 'arg': self.__to_value(arg)})
            val = self.req.recv_json()
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
            return pyval
        # VRecord
        elif isinstance(pyval, dict):
            val = {'tag': 'record'}
            val['fields'] = [[{'tag': 'Name', 'contents': k}, self.__to_value(v)] for k,v in pyval.items()]
            return val
        # VTuple
        elif isinstance(pyval, tuple):
            return {'tag': 'tuple', 'values': [self.__to_value(v) for v in pyval]}
        # VSeq
        elif isinstance(pyval, list):
            # TODO: assert homogeneous, set isWord
            return {'tag': 'sequence', 'isWord': False, 'elements': [self.__to_value(v) for v in pyval]}
        # VWord
        elif isinstance(pyval, BitVector):
            return {'tag': 'bitvector', 'width': pyval.length(), 'value': int(pyval)}
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
        self.req.send_json({'tag': 'setOpt', 'key': k, 'value': v})
        return self.req.recv_json()

    def load_module(self, filepath):
        self.req.send_json({'tag': 'loadModule', 'filePath': filepath})
        return self.req.recv_json()

    def browse(self):
        self.req.send_json({'tag': 'browse'})
        return self.req.recv_json()

    def exit(self):
        self.req.send_json({'tag': 'exit'})
        return self.req.recv_json()

if __name__ == '__main__':
    cry = Cryptol("tcp://127.0.0.1:5555")
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
