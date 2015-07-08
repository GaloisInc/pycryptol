# -*- coding: utf-8 -*-
# pylint: disable=too-many-return-statements,no-member
"""An interface to the Cryptol interpreter.


"""

from BitVector import BitVector
import atexit
import os
import subprocess
import zmq

class Cryptol(object):
    """A Cryptol interpreter session.

    Instances of this class are sessions with the Cryptol server. The
    main way to use one of these instances is to call :meth:`load_module`
    or :meth:`prelude`.

    :param cryptol_server: The path to the Cryptol server executable

    :param addr: The interface on which to bind the Cryptol server

    :param port: The port on which to bind the Cryptol server

    :param spawn: Spawn a `cryptol-server`, or connect to an
      already-running one?

    """
    def __init__(self,
                 cryptol_server='cryptol-server',
                 addr='tcp://127.0.0.1',
                 port=5555,
                 spawn=True):
        self._loaded_modules = []
        self.__ctx = zmq.Context()
        self.__addr = addr

        if spawn:
            # Start the server
            null = open(os.devnull, 'wb')
            self.__server = subprocess.Popen([cryptol_server, str(port)],
                                             stdin=subprocess.PIPE,
                                             stdout=null,
                                             stderr=null)
        self.__main_req = self.__ctx.socket(zmq.REQ)
        self.__main_req.connect(self.__addr + ':' + str(port))
        atexit.register(self.exit)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.exit()
        return None

    def exit(self):
        """Close the session.

        Any modules loaded in this session will be invalid after
        calling this method.

        """
        for mod in self._loaded_modules:
            mod.exit()
        self.__main_req.close()
        self.__ctx.destroy()
        if self.__server:
            self.__server.terminate()

    def load_module(self, filepath):
        """Load a Cryptol module.

        Returns a Python object with attributes corresponding to
        constants and methods corresponding to functions defined in
        the Cryptol module.

        :param filepath: The filepath of the Cryptol module to load

        """
        self.__main_req.send_json({'tag': 'connect'})
        resp = self.__main_req.recv_json()
        # print 'response: ' + str(resp)
        worker_port = resp['port']
        req = self.__ctx.socket(zmq.REQ)
        req.connect(self.__addr + ':' + str(worker_port))

        mod = Cryptol._CryptolModule(self, req, filepath)
        self._loaded_modules.append(mod)
        return mod

    def prelude(self):
        """Load the Cryptol prelude."""
        return self.load_module('/Users/acfoltzer/src/cryptol/lib/Cryptol.cry')

    class _CryptolModule(object):

        def __init__(self, cry_session, req, filepath):
            self.__cry_session = cry_session
            self.__req = req
            self.__req.send_json({'tag': 'loadModule', 'filePath': filepath})
            self.__req.recv_json()
            self.__req.send_json({'tag': 'browse'})
            tl_decls = self.__req.recv_json()['decls']['ifDecls']
            for decl in tl_decls:
                val = self.eval(decl)
                # give the proper name to the value
                val.__name__ = decl
                # assign it to the object under construction; this
                # uses setattr so that the name used is dynamic
                setattr(self.__class__, decl, val)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self.exit()
            return None

        def __tag_expr(self, tag, expr):
            """Send a command with a string argument to the Cryptol interpreter.

            :param tag: The tag to include in the JSON message

            :param expr: The string to include as the `expr` parameter

            """
            paren_expr = '(%s)' % expr
            print paren_expr
            self.__req.send_json({'tag': tag, 'expr': paren_expr})
            resp = self.__req.recv_json()
            return resp

        def __from_value(self, val):
            """Convert a JSON-formatted Cryptol value to a Python value."""
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
                return BitVector(bitlist=[self.__from_value(elt)
                                          for elt in val['sequence']['elements']])
            if 'sequence' in val and not val['sequence']['isWord']:
                return [self.__from_value(elt)
                        for elt in val['sequence']['elements']]
            # VWord
            if 'word' in val:
                bv = val['word']['bitvector']
                intval = bv['value']
                width = bv['width']
                if width == 0:
                    return None
                else:
                    return BitVector(intVal=intval % (2**width), size=width)
            raise ValueError('Could not convert message to value: %s' % val)

        def __from_funvalue(self, handle):
            """Convert a JSON-formatted Cryptol closure to a Python function.

            This is separated out from :meth:`__from_value` since the
            Cryptol server tags closure messages differently from regular
            values.

            """
            def clos(self, arg):
                self.__req.send_json({'tag': 'applyFun',
                                      'handle': handle,
                                      'arg': self.__to_value(arg)})
                val = self.__req.recv_json()
                if val['tag'] == 'value':
                    return self.__from_value(val['value'])
                elif val['tag'] == 'funValue':
                    return self.__from_funvalue(val['handle'])
                else:
                    raise ValueError(
                        'No value returned from applying Cryptol function; '
                        'instead got %s' % str(val))
            setattr(clos, '__name__', '<cryptol_closure>')
            return clos

        def __to_value(self, pyval):
            # VBit
            if isinstance(pyval, bool):
                return {'bit': pyval}
            # VRecord
            elif isinstance(pyval, dict):
                return {'record': [[{'Name': k}, self.__to_value(v)]
                                   for k, v in pyval.items()]}
            # VTuple
            elif isinstance(pyval, tuple):
                return {'tuple': [self.__to_value(v) for v in pyval]}
            # VSeq
            elif isinstance(pyval, list):
                # TODO: assert homogeneous, set isWord
                return {'sequence':
                        {'isWord': False,
                         'elements': [self.__to_value(v) for v in pyval]}}
            # VWord
            elif isinstance(pyval, BitVector):
                return {'word':
                        {'bitvector':
                         {'width': pyval.length(), 'value': int(pyval)}}}
            else:
                raise ValueError(
                    'Unable to convert Python value into '
                    'Cryptol value %s' % str(pyval))

        def eval(self, expr):
            val = self.__tag_expr('evalExpr', expr)
            if val['tag'] == 'value':
                return self.__from_value(val['value'])
            elif val['tag'] == 'funValue':
                return self.__from_funvalue(val['handle'])
            else:
                raise ValueError(
                    'Cryptol evaluation returned a non-value '
                    'message: %s' % val)

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
            self.__req.send_json({'tag': 'setOpt', 'key': k, 'value': v})
            return self.__req.recv_json()

        def browse(self):
            self.__req.send_json({'tag': 'browse'})
            return self.__req.recv_json()

        def exit(self):
            self.__cry_session._loaded_modules.remove(self)
            self.__req.send_json({'tag': 'exit'})
            return self.__req.recv_json()


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
    cry = Cryptol(spawn=False)
    # print cry
    with cry.load_module('/Users/acfoltzer/src/cryptol/lib/Cryptol.cry') as prelude:
        exp = '\\x -> x + 0x4'
        print '*** eval(' + exp + ')'
        fh = prelude.eval(exp)
        print fh
        modules = [prelude]
        modules.append(cry.load_module('/Users/acfoltzer/src/cryptol/docs/ProgrammingCryptol/aes/AES.cry'))
        print modules
        modules.remove(prelude)
        print modules
    # print '*** eval(1+1)'
    # print cry.eval('1+1')
    # print '*** typeof(0xdeadbeef)'

    # print cry.typeof('0xdeadbeef')
    # print '*** check(\\x -> x + 0x00 == x)'
    # print cry.check('\\x -> x + 0x00 == x')
    # print '*** exhaust(\\x -> x + 0x00 == x)'
    # print cry.exhaust('\\x -> x + 0x00 == x')
    # print '*** prove(\\x -> x + 0x00 == x)'
    # print cry.prove('\\x -> x + 0x00 == x')
    # print '*** sat(\\x -> x + 0x00 == x)'
    # print cry.sat('\\x -> x + 0x00 == x')
    # print '*** setopt(prover, z3)'
    # print cry.setopt('prover', 'z3')
    # print '*** sat(\\x -> x + 0x00 == x)'
    # print cry.sat('\\x -> x + 0x00 == x')
    # print '*** browse'
    # print cry.browse()
