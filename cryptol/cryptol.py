# -*- coding: utf-8 -*-
# pylint: disable=too-many-return-statements,no-member,fixme
"""An interface to the Cryptol interpreter."""

from BitVector import BitVector
import atexit
import enum
import os
import string
import re
import subprocess
import weakref
import zmq

class Provers(enum.Enum):
    """Available provers for Cryptol"""

    ANY = 'any'
    """Use all available provers, returning the first answer"""
    ABC = 'abc'
    """Use `ABC <http://www.eecs.berkeley.edu/~alanmi/abc/>`_"""
    BOOLECTOR = 'boolector'
    """Use `Boolector <http://fmv.jku.at/boolector/>`_"""
    CVC4 = 'cvc4'
    """Use `CVC4 <http://cvc4.cs.nyu.edu/web/>`_"""
    MATHSAT = 'mathsat'
    """Use `MathSAT <http://mathsat.fbk.eu/>`_"""
    YICES = 'yices'
    """Use `Yices <http://yices.csl.sri.com/>`_"""
    Z3 = 'z3'
    """Use `Z3 <https://github.com/Z3Prover/z3>`_"""

class Cryptol(object):
    """A Cryptol interpreter session.

    Instances of this class are sessions with the Cryptol server. The
    main way to use one of these instances is to call
    :meth:`.load_module` or :meth:`.prelude`.

    :param str cryptol_server: The path to the Cryptol server executable

    :param str addr: The interface on which to bind the Cryptol server

    :param int port: The port on which to bind the Cryptol server

    :param bool spawn: Spawn a ``cryptol-server``, or connect to an
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

    This class is the basis for the objects returned by
    :meth:`.load_module` and :meth:`.prelude`.

    :param Socket req: The request socket for this module context

    :param str filepath: The filepath of the Cryptol module to load, or
        ``None`` for loading only the prelude

    """
    __identifier = re.compile(r"^[a-zA-Z_]\w*\Z")

    def __init__(self, req, filepath=None):
        self.__ascii = False
        self.__base = 16
        self.__ite_solver = False
        self.__mono_binds = True
        self.__prover = Provers.CVC4
        self.__req = req
        if filepath is not None:
            self.__load_module(filepath)
        self.__req.send_json({'tag': 'browse'})
        browse_resp = self.__req.recv_json()
        tl_decls = browse_resp['decls']['ifDecls']
        for decl in tl_decls:
            name = decl['ifDeclName']['nIdent'][1]
            # TODO: handle infix operators. Right now they can be
            # accessed by strings through :meth:`.eval`, but since new
            # infix operators can't be defined in Python, we can't add
            # them to the returned object
            is_infix = decl['ifDeclInfix']
            if is_infix:
                continue
            # TODO: properly handle polymorphic declarations
            tvars = decl['ifDeclSig']['sVars']
            if len(tvars) is not 0:
                continue
            val = self.eval(name)
            # give the proper name to the value, if it can be
            # set. First, check to make sure we're not naming a base
            # type, then check whether the name is a valid Python
            # identifier. TODO: name mangling for invalid identifiers?
            if (hasattr(val, '__name__') and
                    re.match(_CryptolModule.__identifier, decl) is not None):
                val.__name__ = decl.encode('utf-8')
            # set the docstring if available and settable
            if 'ifDeclDoc' in decl:
                try:
                    val.__doc__ = decl['ifDeclDoc'].encode('utf-8')
                except AttributeError:
                    pass
            # assign it to the object under construction; this
            # uses setattr so that the name used is dynamic
            setattr(self.__class__, name, val)

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

    def __tag_expr(self, tag, expr, fmtargs):
        """Send a command with a string argument to the Cryptol interpreter.

        :param str tag: The tag to include in the JSON message

        :param str expr: The string to include as the ``expr`` parameter

        :param fmtargs: The values to substitute in for ``?`` in
            ``expr`` (see :meth:`.template`)

        """
        expr = _CryptolModule.template(expr, fmtargs)
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
        # VFun TODO: this only arises when functions are nested within
        # other structures. Make the server handle this case with a
        # funvalue message
        if 'function' in val:
            return None
        raise ValueError('Could not convert message to value: %s' % val)

    def __from_funvalue(self, handle):
        """Convert a JSON-formatted Cryptol closure to a Python function.

        This is separated out from :meth:`.__from_value` since the
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
        """Convert a Python value to a JSON-formatted Cryptol value."""
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
            # TODO: convert strings to ASCII?
            raise ValueError(
                'Unable to convert Python value into '
                'Cryptol value %s' % str(pyval))

    def eval(self, expr, fmtargs=()):
        """Evaluate a Cryptol expression in this module's context.

        :param str expr: The expression to evaluate

        :param fmtargs: The values to substitute in for ``?`` in
            ``expr`` (see :meth:`.template`)

        :return: A Python value representing the result of evaluating
            ``expr``

        :raises CryptolError: if an error occurs during Cryptol
            parsing, typechecking, or evaluation

        :raises ValueError: if an unexpected message is returned from
            the Cryptol server

        """
        val = self.__tag_expr('evalExpr', expr, fmtargs)
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

    def typeof(self, expr, fmtargs=()):
        """Get the type of a Cryptol expression.

        :param str expr: The expression to typecheck

        :param fmtargs: The values to substitute in for ``?`` in
            ``expr`` (see :meth:`.template`)

        :return str: The pretty-printed representation of the type

        :raises CryptolError: if an error occurs during Cryptol
            parsing or typechecking

        :raises ValueError: if an unexpected message is returned from
            the Cryptol server

        """
        # TODO: design Python representation of Cryptol types for a
        # semantically-meaningful return value
        resp = self.__tag_expr('typeOf', expr, fmtargs)
        if resp['tag'] == 'type':
            return resp['pp']
        elif resp['tag'] == 'interactiveError':
            raise CryptolError(resp['pp'])
        else:
            raise ValueError(
                'Cryptol typechecking returned a non-type '
                'message: %s' % resp)

    def check(self, expr, fmtargs=()):
        """Randomly test a Cryptol property."""
        # TODO: return counterexample value
        return self.__tag_expr('check', expr, fmtargs)

    def exhaust(self, expr, fmtargs=()):
        """Exhaustively check a Cryptol property."""
        # TODO: return counterexample value
        return self.__tag_expr('exhaust', expr, fmtargs)

    def prove(self, expr, fmtargs=(), prover=Provers.CVC4, ite_solver=False):
        """Prove validity of a Cryptol property, or find a counterexample.

        :param str expr: The property to satisfy

        :param fmtargs: The values to substitute in for ``?`` in
            ``expr`` (see :meth:`.template`)

        :return: ``None`` if the property is valid, or a tuple of Python
            values if a counterexample is found

        :raises ProverError: if an error occurs during prover invocation

        :raises CryptolError: if an error occurs during Cryptol
            parsing, typechecking, evaluation, or symbolic simulation

        :raises ValueError: if an unexpected message is returned from
            the Cryptol server

        """
        # TODO: returning `None` is really ugly; should have some sort
        # of solverresult api

        # set keywords
        self.setopt('prover', prover.value)
        self.setopt('iteSolver', _bool_to_opt(ite_solver))

        resp = self.__tag_expr('prove', expr, fmtargs)
        if resp['tag'] == 'prove':
            if resp['counterexample'] is not None:
                return tuple([self.__from_value(arg)
                              for arg in resp['counterexample']])
            else:
                return None
        elif resp['tag'] == 'proverError':
            raise ProverError(resp['message'])
        elif resp['tag'] == 'interactiveError':
            raise CryptolError(resp['pp'])
        else:
            raise ValueError(
                'Cryptol prove command returned an invalid '
                'message: %s' % resp)

    def sat(self, expr, fmtargs=(), sat_num=1, prover=Provers.CVC4, ite_solver=False):
        """Find satisfying assignments for a Cryptol property.

        :param str expr: The property to satisfy

        :param fmtargs: The values to substitute in for ``?`` in
            ``expr`` (see :meth:`.template`)

        :param int sat_num: The maximum number of satisfying
            assignments to return; use ``None`` for no maximum

        :param Provers prover: The prover to use

        :param bool ite_solver: Whether to use the solver during
            symbolic execution; can prevent non-termination at the
            cost of performance

        :return: A list containing the satisfying assignments as
            tuples of Python values

        :raises ProverError: if an error occurs during prover invocation

        :raises CryptolError: if an error occurs during Cryptol
            parsing, typechecking, evaluation, or symbolic simulation

        :raises ValueError: if an unexpected message is returned from
            the Cryptol server

        """
        # TODO: disambiguate sat with no arguments from unsat

        # set keywords
        if sat_num is None:
            self.setopt('satNum', 'all')
        else:
            self.setopt('satNum', str(sat_num))
        self.setopt('prover', prover.value)
        self.setopt('iteSolver', _bool_to_opt(ite_solver))

        resp = self.__tag_expr('sat', expr, fmtargs)
        if resp['tag'] == 'sat':
            return [tuple([self.__from_value(arg) for arg in assignment])
                    for assignment in resp['assignments']]
        elif resp['tag'] == 'proverError':
            raise ProverError(resp['message'])
        elif resp['tag'] == 'interactiveError':
            raise CryptolError(resp['pp'])
        else:
            raise ValueError(
                'Cryptol SAT checking returned an invalid '
                'message: %s' % resp)

    def setopt(self, option, value):
        """Set an option in the Cryptol session for this module.

        .. note:: This method is going away in the near future, but is
            here for completeness at the moment. Values set here may
            be overwritten by calls to :meth:`.prove` and
            :meth:`.sat`, among others.

        :param str option: The option to set

        :param str value: The value to assign to ``option``

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

    @staticmethod
    def to_expr(pyval):
        """Convert a Python value to a Cryptol expression"""
        # boolean -> Bit
        if isinstance(pyval, bool):
            return str(pyval)
        # int -> decimal literal
        if isinstance(pyval, int):
            return str(pyval)
        # dict -> record
        elif isinstance(pyval, dict):
            fields = ['%s = %s' % (k, _CryptolModule.to_expr(v))
                      for k, v in pyval.items()]
            return '{%s}' % ', '.join(fields)
        # tuple -> tuple
        elif isinstance(pyval, tuple):
            elts = [_CryptolModule.to_expr(v) for v in pyval]
            return '(%s)' % ', '.join(elts)
        # list of length n containing a -> [n]a
        elif isinstance(pyval, list):
            elts = [_CryptolModule.to_expr(v) for v in pyval]
            return '[%s]' % ', '.join(elts)
        # BitVector of length n -> [n]
        elif isinstance(pyval, BitVector):
            return '%d : [%d]' % (int(pyval), pyval.length())
        else:
            # TODO: convert strings to ASCII?
            raise ValueError(
                'Unable to convert Python value into '
                'Cryptol expression: %s' % str(pyval))

    @staticmethod
    def template(template, args=()):
        """Fill in a Cryptol template string.

        This replaces instances of ``?`` with the provided tuple of
        arguments converted by :meth:`.to_expr`, similarly to a format
        string.

        .. note:: The number of ``?`` s in the template and the number of
            extra arguments must be equal.

        :param str template: The template string

        :param args: A tuple of values to splice into the template, or
            a non-tuple value if only one hole exists (to splice a
            single tuple, pass it in a Python 1-tuple, e.g., ``((True,
            False),)`` .

        :raises TypeError: if the number of arguments does not match
            the number of holes in the template

        """
        holes = string.count(template, '?')
        if not isinstance(args, tuple):
            args = (args,)
        if len(args) < holes:
            raise TypeError(
                'not all arguments converted during Cryptol string templating')
        if len(args) > holes:
            raise TypeError(
                'not enough arguments for Cryptol template string')
        result = template
        for arg in args:
            result = string.replace(result, '?', _CryptolModule.to_expr(arg), 1)
        return result

class CryptolError(Exception):
    """Base class for all errors arising from Cryptol"""
    # TODO: add a class hierarchy to break down the different types of
    # Cryptol errors
    pass

class ProverError(CryptolError):
    """An error arising from the prover configured for Cryptol"""
    pass

def _bool_to_opt(boolean):
    """Convert a boolean to ``on`` or ``off``"""
    if boolean:
        return 'on'
    else:
        return 'off'

def _is_function(sch):
    """Is a JSON Schema a function type?"""
    ans = False
    try:
        ans = 'TCFun' in sch['sType']['TCon'][0]['TC']
    except (IndexError, KeyError):
        pass
    return ans
