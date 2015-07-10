# -*- coding: utf-8 -*-
# pylint: disable=too-many-return-statements,no-member,fixme
"""An interface to the Cryptol interpreter."""

from BitVector import BitVector
import atexit
import os
import re
import subprocess
import weakref
import zmq

class Cryptol(object):
    """A Cryptol interpreter session.

    Instances of this class are sessions with the Cryptol server. The
    main way to use one of these instances is to call :meth:`load_module`
    or :meth:`prelude`.

    :param str cryptol_server: The path to the Cryptol server executable

    :param str addr: The interface on which to bind the Cryptol server

    :param int port: The port on which to bind the Cryptol server

    :param bool spawn: Spawn a `cryptol-server`, or connect to an
      already-running one?

    """
    def __init__(self,
                 cryptol_server='cryptol-server',
                 addr='tcp://127.0.0.1',
                 port=5555,
                 spawn=True):
        self.__loaded_modules = []
        self.__ctx = zmq.Context()
        self.__addr = addr

        if spawn:
            # Start the server
            null = open(os.devnull, 'wb')
            self.__server = subprocess.Popen([cryptol_server, str(port)],
                                             stdin=subprocess.PIPE,
                                             stdout=null,
                                             stderr=null)
        else:
            self.__server = False
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
        for mod_ref in self.__loaded_modules:
            mod = mod_ref()
            if mod is not None:
                mod.exit()
        if not self.__main_req.closed:
            self.__main_req.close()
        self.__ctx.destroy()
        if self.__server:
            self.__server.terminate()

    def load_module(self, filepath):
        """Load a Cryptol module.

        Returns a Python object with attributes corresponding to
        constants and methods corresponding to functions defined in
        the Cryptol module.

        :param str filepath: The filepath of the Cryptol module to load

        """
        req = self.__new_client()
        # TODO: get the module name from the AST, don't just guess
        # from the filepath
        mod_name = os.path.splitext(os.path.basename(filepath))[0]
        cls = type("%s <Cryptol>" % mod_name, (_CryptolModule,), {})
        mod = cls(req, filepath)
        self.__loaded_modules.append(weakref.ref(mod))
        return mod

    def prelude(self):
        """Load the Cryptol prelude."""
        req = self.__new_client()
        cls = type('Prelude <Cryptol>', (_CryptolModule,), {})
        mod = cls(req)
        self.__loaded_modules.append(weakref.ref(mod))
        return mod

    def __new_client(self):
        """Start up a new REPL session client."""
        self.__main_req.send_json({'tag': 'connect'})
        resp = self.__main_req.recv_json()
        worker_port = resp['port']
        req = self.__ctx.socket(zmq.REQ)
        req.connect(self.__addr + ':' + str(worker_port))
        return req

class _CryptolModule(object):
    """Abstract class for Cryptol modules.

    .. note:: Users of this module should not instantiate this class
        directly.

    This class is the basis for the object returned by
    :meth:`load_module`.

    :param Socket req: The request socket for this module context

    :param str filepath: The filepath of the Cryptol module to load, or
        `None` for loading only the prelude

    """
    __identifier = re.compile(r"^[a-zA-Z_]\w*\Z")

    def __init__(self, req, filepath=None):
        self.__req = req
        if filepath is not None:
            self.__load_module(filepath)
        self.__req.send_json({'tag': 'browse'})
        browse_resp = self.__req.recv_json()
        tl_decls = browse_resp['decls']['ifDecls']
        for decl in tl_decls:
            # TODO: handle infix operators. Right now they can be
            # accessed by strings through :meth:`eval`, but since new
            # infix operators can't be defined in Python, we can't add
            # them to the returned object
            is_infix = tl_decls[decl][0]['ifDeclInfix']
            if is_infix:
                continue
            # TODO: properly handle polymorphic declarations
            tvars = tl_decls[decl][0]['ifDeclSig']['sVars']
            if len(tvars) is not 0:
                continue
            val = self.eval(decl)
            # give the proper name to the value, if it can be
            # set. First, check to make sure we're not naming a base
            # type, then check whether the name is a valid Python
            # identifier. TODO: name mangling for invalid identifiers?
            if (hasattr(val, '__name__') and
                    re.match(_CryptolModule.__identifier, decl) is not None):
                val.__name__ = decl.encode('utf-8')
            # set the docstring if available and settable
            if 'ifDeclDoc' in tl_decls[decl][0]:
                try:
                    val.__doc__ = tl_decls[decl][0]['ifDeclDoc'].encode('utf-8')
                except AttributeError:
                    pass
            # assign it to the object under construction; this
            # uses setattr so that the name used is dynamic
            setattr(self.__class__, decl, val)

    def __load_module(self, filepath):
        """Initialize this module with the file at the given path

        :param str filepath: The filepath of the Cryptol module to load

        :raises CryptolError: if the module does not load successfully

        """
        self.__req.send_json({'tag': 'loadModule', 'filePath': filepath})
        load_resp = self.__req.recv_json()
        if load_resp['tag'] != 'ok':
            raise CryptolError(load_resp)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.exit()

    def __del__(self):
        self.exit()

    def __tag_expr(self, tag, expr):
        """Send a command with a string argument to the Cryptol interpreter.

        :param str tag: The tag to include in the JSON message

        :param str expr: The string to include as the `expr` parameter

        """
        self.__req.send_json({'tag': tag, 'expr': expr})
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
            """Closure for callable Cryptol function"""
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
        """Convert a Python value to a JSON-formatted Cryptol value"""
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
        """Evaluate a Cryptol expression in this module's context.

        :param str expr: The expression to evaluate

        :return: A Python value representing the result of evaluating
            `expr`

        :raises CryptolError: if an error occurs during Cryptol
            parsing, typechecking, or evaluation

        :raises ValueError: if an unexpected message is returned from
            the Cryptol server

        """
        val = self.__tag_expr('evalExpr', expr)
        if val['tag'] == 'value':
            return self.__from_value(val['value'])
        elif val['tag'] == 'funValue':
            return self.__from_funvalue(val['handle'])
        elif val['tag'] == 'interactiveError':
            raise CryptolError(val['pp'])
        else:
            raise ValueError(
                'Cryptol evaluation returned a non-value '
                'message: %s' % val)

    def typeof(self, expr):
        """Get the type of a Cryptol expression.

        :param str expr: The expression to typecheck

        :return str: The pretty-printed representation of the type

        :raises CryptolError: if an error occurs during Cryptol
            parsing or typechecking

        :raises ValueError: if an unexpected message is returned from
            the Cryptol server

        """
        # TODO: design Python representation of Cryptol types for a
        # semantically-meaningful return value
        resp = self.__tag_expr('typeOf', expr)
        if resp['tag'] == 'type':
            return resp['pp']
        elif resp['tag'] == 'interactiveError':
            raise CryptolError(resp['pp'])
        else:
            raise ValueError(
                'Cryptol typechecking returned a non-type '
                'message: %s' % resp)

    def check(self, expr):
        """Randomly test a Cryptol property."""
        # TODO: return counterexample value
        return self.__tag_expr('check', expr)

    def exhaust(self, expr):
        """Exhaustively check a Cryptol property."""
        # TODO: return counterexample value
        return self.__tag_expr('exhaust', expr)

    def prove(self, expr):
        """Prove a Cryptol property."""
        # TODO: return counterexample value
        return self.__tag_expr('prove', expr)

    def sat(self, expr):
        """Find a satisfying assignment for a Cryptol property."""
        # TODO: return satisfying assignment value
        return self.__tag_expr('sat', expr)

    def setopt(self, option, value):
        """Set an option in the Cryptol session for this module.

        :param str option: The option to set

        :param str value: The value to assign to `option`

        """
        # TODO: add more examples, special-case these into methods
        # like _CryptolModule.set_base, etc
        self.__req.send_json({'tag': 'setOpt', 'key': option, 'value': value})
        return self.__req.recv_json()

    def browse(self):
        """Browse the definitions in scope in this module."""
        # TODO: return these in a cleaner structure, perhaps combined
        # with the type information that typeof will return
        self.__req.send_json({'tag': 'browse'})
        return self.__req.recv_json()

    def exit(self):
        """End the Cryptol session for this module.

        .. note:: It is usually not necessary to call this method
            unless this instance might not be garbage-collected.

        """
        if not self.__req.closed:
            self.__req.send_json({'tag': 'exit'})
            self.__req.recv_json()
            self.__req.close()


class CryptolError(Exception):
    """Base class for all errors arising from Cryptol"""
    # TODO: add a class hierarchy to break down the different types of
    # Cryptol errors
    pass


def _is_function(sch):
    """Is a JSON Schema a function type?"""
    ans = False
    try:
        ans = 'TCFun' in sch['sType']['TCon'][0]['TC']
    except (IndexError, KeyError):
        pass
    return ans
