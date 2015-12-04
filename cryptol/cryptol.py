# -*- coding: utf-8 -*-
# pylint: disable=too-many-return-statements,no-member,fixme
"""An interface to the Cryptol interpreter."""

from BitVector import BitVector
import atexit
import enum
import os
import string
import time
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

class ProofResult(object):
    """The result of a call to :meth:`.prove`"""

    def __init__(self, is_valid, cex):
        if is_valid and cex is not None:
            raise PycryptolInternalError(
                'Counterexample given for valid property')
        self.__is_valid = is_valid
        self.__cex = cex

    def __str__(self):
        if self.__is_valid:
            return "valid"
        else:
            return "invalid"

    def is_valid(self):
        """Is the property valid?"""
        return self.__is_valid

    def has_counterexample(self):
        """Does the property have a counterexample?"""
        return self.__cex is not None

    def get_counterexample(self):
        """Return the counterexample as a tuple of arguments"""
        if self.__cex is None:
            raise ValueError('No counterexample for valid property')
        return self.__cex

class SatResult(object):
    """The result of a call to :meth:`.sat` with ``sat_num=1``"""

    def __init__(self, is_sat, args):
        if is_sat and args is None:
            raise PycryptolInternalError(
                'No satisfying assignment given for satisfiable property')
        self.__is_sat = is_sat
        self.__args = args

    def __str__(self):
        if self.__is_sat:
            return 'sat'
        else:
            return 'unsat'

    def is_sat(self):
        """Is the property satisfiable?"""
        return self.__is_sat

    def has_assignment(self):
        """Does the property have a satisfying assignment?"""
        return self.__args is not None

    def get_assignment(self):
        """Return the satisfying assignment as a tuple of arguments"""
        if self.__args is None:
            raise ValueError('No satisfying assignment for unsat property')
        return self.__args

class AllSatResult(object):
    """The result of a call to :meth:`.sat` with ``sat_num`` other than ``1``"""

    def __init__(self, is_sat, argss):
        if is_sat and argss is None:
            raise PycryptolInternalError(
                'No satisfying assignments given for satisfiable property')
        self.__is_sat = is_sat
        self.__argss = argss

    def __str__(self):
        if self.__is_sat:
            return 'sat'
        else:
            return 'unsat'

    def is_sat(self):
        """Is the property satisfiable?"""
        return self.__is_sat

    def assignment_count(self):
        """How many satisfying assignments were found?"""
        if self.__argss is None:
            raise ValueError('No satisfying assignments for unsat property')
        return len(self.__argss)

    def get_assignments(self):
        """Return the satisfying assignments as a list of tuples of arguments"""
        if self.__argss is None:
            raise ValueError('No satisfying assignments for unsat property')
        return self.__argss

class Cryptol(object):
    """A Cryptol interpreter session.

    Instances of this class are sessions with the Cryptol server. The
    main way to use one of these instances is to call
    :meth:`.load_module` or :meth:`.prelude`.

    :param str cryptol_server: The path to the Cryptol server
        executable; pass ``None`` to instead connect to an
        already-running server

    :param str addr: The interface on which to bind the Cryptol server

    :param int port: The port on which to bind the Cryptol server

    :raises CryptolServerError: if the ``cryptol_server`` executable
        can't be found or exits unexpectedly

    """
    def __init__(self,
                 cryptol_server='cryptol-server',
                 addr='tcp://127.0.0.1',
                 port=5555):
        self.__loaded_modules = []
        self.__ctx = zmq.Context()
        self.__addr = addr

        if cryptol_server is not None:
            # Start the server
            null = open(os.devnull, 'wb')
            try:
                args = [cryptol_server,
                        '--port', str(port),
                        '--mask-interrupts']
                self.__server = subprocess.Popen(args,
                                                 stdin=subprocess.PIPE,
                                                 stdout=null,
                                                 stderr=null,
                                                 shell=True)
            except OSError as err:
                if err.errno == os.errno.ENOENT:
                    raise CryptolServerError(
                        u'Could not find Cryptol server executable {!r}.\n'
                        'Make sure it is on your system path, or pass a '
                        'different path for the cryptol_server argument.'
                        .format(cryptol_server)
                        )
                else:
                    raise

            # wait a little bit to make sure the server doesn't
            # promptly exit
            time.sleep(0.01)
            result = self.__server.poll()
            if result is not None:
                raise CryptolServerError(
                    u'Cryptol server executable {!r} exited unexpectedly '
                    'with exit code {:d}'.format(cryptol_server, result)
                    )
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
        if not self.__main_req.closed and self.__server:
            self.__main_req.send_json({'tag': 'exit'}, flags=zmq.NOBLOCK)
            self.__main_req.close()
        if not self.__ctx.closed:
            self.__ctx.destroy()
        if self.__server and self.__server.poll() is not None:
            time.sleep(0.01)
            self.__server.terminate()

    def load_module(self, filepath):
        """Load a Cryptol module.

        Returns a Python object with attributes corresponding to
        constants and methods corresponding to functions defined in
        the Cryptol module.

        :param str filepath: The filepath of the Cryptol module to load

        """
        port, req = self.__new_client()
        # TODO: get the module name from the AST, don't just guess
        # from the filepath
        mod_name = os.path.splitext(
            os.path.basename(filepath))[0].encode('ascii', 'replace')
        cls = type('{} <Cryptol>'.format(mod_name), (_CryptolModule,), {})
        mod = cls(port, req, self.__main_req, filepath)
        self.__loaded_modules.append(weakref.ref(mod))
        return mod

    def prelude(self):
        """Load the Cryptol prelude."""
        port, req = self.__new_client()
        cls = type('Prelude <Cryptol>', (_CryptolModule,), {})
        mod = cls(port, req, self.__main_req)
        self.__loaded_modules.append(weakref.ref(mod))
        return mod

    def __new_client(self):
        """Start up a new REPL session client."""
        self.__main_req.send_json({'tag': 'connect'})
        resp = self.__main_req.recv_json()
        worker_port = resp['port']
        req = self.__ctx.socket(zmq.REQ)
        req.connect(self.__addr + ':' + str(worker_port))
        return (worker_port, req)

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

    def __init__(self, port, req, control_req, filepath=None):
        self.__decls = {}
        self.__ascii = False
        self.__base = 16
        self.__mono_binds = True
        self.__prover = Provers.CVC4
        self.__port = port
        self.__req = req
        self.__control_req = control_req
        if filepath is None:
            self.__load_prelude()
        else:
            self.__load_module(filepath)
        self.__req.send_json({'tag': 'browse'})
        browse_resp = self.__try_recv_json()
        tl_decls = browse_resp['decls']['ifDecls']
        for decl in tl_decls:
            name = decl['ifDeclName']['nIdent'][1]

            # TODO: properly handle polymorphic declarations
            tvars = decl['ifDeclSig']['sVars']
            if len(tvars) is not 0:
                # TODO: warn
                continue

            # Run the evaluation
            val_resp = self.__tag_expr('evalExpr', u'({})'.format(name), ())
            if val_resp['tag'] == 'value':
                val = self.__from_value(val_resp['value'])
                sval = val
            elif val_resp['tag'] == 'funValue':
                val = self.__from_funvalue(val_resp['handle'], static=False)
                sval = self.__from_funvalue(val_resp['handle'], static=True)
            elif val_resp['tag'] == 'interactiveError':
                raise CryptolError(val_resp['pp'])
            else:
                raise PycryptolInternalError(
                    u'Cryptol evaluation returned a non-value '
                    'message: {}'.format(val_resp))

            # set the name, if possible
            try:
                val.__name__ = name.encode('utf-8')
                sval.__name__ = name.encode('utf-8')
            except AttributeError:
                pass

            # set the docstring if available and settable
            if 'ifDeclDoc' in decl:
                try:
                    val.__doc__ = decl['ifDeclDoc'].encode('utf-8')
                    sval.__doc__ = decl['ifDeclDoc'].encode('utf-8')
                except AttributeError:
                    pass

            # at this point the decl is ready to at least be added to
            # the decls dictionary, if not as a member to the class,
            # but interpret it statically
            self.__decls[name] = sval

            # Since new infix operators can't be defined in Python, we
            # can't add them to the returned object, only to the decls
            # dictionary.
            is_infix = decl['ifDeclInfix']
            if is_infix:
                # TODO: warn
                continue

            # filter out invalid identifiers
            if re.match(_CryptolModule.__identifier, name) is None:
                continue

            # make sure the name doesn't already exist in the current
            # object to prevent overwriting things like __class__
            if hasattr(self, name):
                # TODO: warn for collisions
                continue

            # add it to the object under construction
            setattr(self.__class__, name, val)

    def __load_prelude(self):
        """Load the Prelude, leaving it up to the server to find it

        :raises CryptolError: if the prelude does not load successfully

        """
        self.__req.send_json({'tag': 'loadPrelude'})
        load_resp = self.__try_recv_json()
        if load_resp['tag'] != 'ok':
            raise CryptolError(load_resp)

    def __load_module(self, filepath):
        """Initialize this module with the file at the given path

        :param str filepath: The filepath of the Cryptol module to load

        :raises CryptolError: if the module does not load successfully

        """
        self.__req.send_json({'tag': 'loadModule', 'filePath': filepath})
        load_resp = self.__try_recv_json()
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

        :raises TypeError: if the given expression is not a string

        """
        if not isinstance(expr, basestring):
            raise TypeError(
                u'Expected Cryptol expression as string, '
                'got unsupported type {!r}'.format(type(expr).__name__)
                )
        expr = _CryptolModule.template(expr, fmtargs)
        self.__req.send_json({'tag': tag, 'expr': expr})
        resp = self.__try_recv_json()
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
        raise PycryptolInternalError(
            u'Could not convert message to value: {}'.format(val))

    def __from_funvalue(self, handle, static=True):
        """Convert a JSON-formatted Cryptol closure to a Python function.

        This is separated out from :meth:`.__from_value` since the
        Cryptol server tags closure messages differently from regular
        values.

        :param bool static: Whether to return a static function, or a
        method on the current module
        """
        def clos(self, arg):
            """Closure for callable Cryptol function"""
            self.__req.send_json({'tag': 'applyFun',
                                  'handle': handle,
                                  'arg': self.__to_value(arg)})
            val = self.__try_recv_json()
            if val['tag'] == 'value':
                return self.__from_value(val['value'])
            elif val['tag'] == 'funValue':
                return self.__from_funvalue(val['handle'], static)
            else:
                raise PycryptolInternalError(
                    u'No value returned from applying Cryptol function; '
                    'instead got {!s}'.format(val))
        def static_clos(arg):
            """Closure for callable Cryptol function"""
            return clos(self, arg)
        setattr(clos, '__name__', '<cryptol_closure>')
        setattr(static_clos, '__name__', '<cryptol_closure>')
        if static:
            return static_clos
        else:
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
                u'Unable to convert Python value into '
                'Cryptol value {!s}'.format(pyval))

    def decl(self, name):
        """Return a top-level Cryptol declaration in the current module

        Because Cryptol and Python have different syntaxes for
        identifiers, not all Cryptol declarations can be made into
        members on the object returned by :meth:`.load_module`. Use
        this method to access other declarations without reevaluating
        them.

        :param str name: The name of the declaration

        :return: A Python value representing the named declaration

        :raises CryptolError: if the declaration is not in scope

        """
        try:
            return self.__decls[name]
        except KeyError:
            raise CryptolError(u'Value not in scope: {}'.format(name))

    def eval(self, expr, fmtargs=()):

        """Evaluate a Cryptol expression in this module's context.

        :param str expr: The expression to evaluate

        :param fmtargs: The values to substitute in for ``?`` in
            ``expr`` (see :meth:`.template`)

        :return: A Python value representing the result of evaluating
            ``expr``

        :raises CryptolError: if an error occurs during Cryptol
            parsing, typechecking, or evaluation

        """
        val = self.__tag_expr('evalExpr', expr, fmtargs)
        if val['tag'] == 'value':
            return self.__from_value(val['value'])
        elif val['tag'] == 'funValue':
            return self.__from_funvalue(val['handle'])
        elif val['tag'] == 'interactiveError':
            raise CryptolError(val['pp'])
        else:
            raise PycryptolInternalError(
                u'Cryptol evaluation returned a non-value '
                'message: {}'.format(val))

    def typeof(self, expr, fmtargs=()):
        """Get the type of a Cryptol expression.

        :param str expr: The expression to typecheck

        :param fmtargs: The values to substitute in for ``?`` in
            ``expr`` (see :meth:`.template`)

        :return str: The pretty-printed representation of the type

        :raises CryptolError: if an error occurs during Cryptol
            parsing or typechecking

        """
        # TODO: design Python representation of Cryptol types for a
        # semantically-meaningful return value
        resp = self.__tag_expr('typeOf', expr, fmtargs)
        if resp['tag'] == 'type':
            return resp['pp']
        elif resp['tag'] == 'interactiveError':
            raise CryptolError(resp['pp'])
        else:
            raise PycryptolInternalError(
                u'Cryptol typechecking returned a non-type '
                'message: {}'.format(resp))

    def check(self, expr, fmtargs=()):
        """Randomly test a Cryptol property."""
        # TODO: return counterexample value
        return self.__tag_expr('check', expr, fmtargs)

    def exhaust(self, expr, fmtargs=()):
        """Exhaustively check a Cryptol property."""
        # TODO: return counterexample value
        return self.__tag_expr('exhaust', expr, fmtargs)

    def prove(self, expr, fmtargs=(), prover=Provers.CVC4):
        """Prove validity of a Cryptol property, or find a counterexample.

        :param str expr: The property to prove

        :param fmtargs: The values to substitute in for ``?`` in
            ``expr`` (see :meth:`.template`)

        :return: A :class:`.ProofResult` for this property

        :raises ProverError: if an error occurs during prover invocation

        :raises CryptolError: if an error occurs during Cryptol
            parsing, typechecking, evaluation, or symbolic simulation

        """
        # set keywords
        self.setopt('prover', prover.value)

        resp = self.__tag_expr('prove', expr, fmtargs)

        if resp['tag'] == 'prove':
            if resp['counterexample'] is not None:
                args = tuple([self.__from_value(arg)
                              for arg in resp['counterexample']])
                return ProofResult(False, args)
            else:
                return ProofResult(True, None)
        elif resp['tag'] == 'proverError':
            raise ProverError(resp['message'])
        elif resp['tag'] == 'interactiveError':
            raise CryptolError(resp['pp'])
        else:
            raise PycryptolInternalError(
                u'Cryptol prove command returned an invalid '
                'message: {}'.format(resp))

    def sat(self,
            expr,
            fmtargs=(),
            sat_num=1,
            prover=Provers.CVC4):
        """Find satisfying assignments for a Cryptol property.

        :param str expr: The property to satisfy

        :param fmtargs: The values to substitute in for ``?`` in
            ``expr`` (see :meth:`.template`)

        :param int sat_num: The maximum number of satisfying
            assignments to return; use ``None`` for no maximum

        :param Provers prover: The prover to use

        :return: Either :class:`.SatResult` or :class:`.AllSatResult`,
            depending on ``sat_num``

        :raises ProverError: if an error occurs during prover invocation

        :raises CryptolError: if an error occurs during Cryptol
            parsing, typechecking, evaluation, or symbolic simulation

        """
        # set keywords
        if sat_num is None:
            self.setopt('satNum', 'all')
        else:
            self.setopt('satNum', str(sat_num))
        self.setopt('prover', prover.value)

        resp = self.__tag_expr('sat', expr, fmtargs)

        if resp['tag'] == 'sat':
            argss = [tuple([self.__from_value(arg) for arg in assignment])
                     for assignment in resp['assignments']]
            # Return different result types based on ``sat_num``
            if sat_num == 1:
                if len(argss) == 0:
                    return SatResult(False, None)
                elif len(argss) == 1:
                    return SatResult(True, argss[0])
                else:
                    raise PycryptolInternalError(
                        'Multiple satisfying assignments with sat_num != 1')
            else:
                if len(argss) == 0:
                    return AllSatResult(False, None)
                else:
                    return AllSatResult(True, argss)

        elif resp['tag'] == 'proverError':
            raise ProverError(resp['message'])
        elif resp['tag'] == 'interactiveError':
            raise CryptolError(resp['pp'])
        else:
            raise PycryptolInternalError(
                u'Cryptol SAT checking returned an invalid '
                'message: {}'.format(resp))

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
        return self.__try_recv_json()

    def browse(self):
        """Browse the definitions in scope in this module."""
        # TODO: return these in a cleaner structure, perhaps combined
        # with the type information that typeof will return
        self.__req.send_json({'tag': 'browse'})
        return self.__try_recv_json()

    def exit(self):
        """End the Cryptol session for this module.

        .. note:: It is usually not necessary to call this method
            unless this instance might not be garbage-collected.

        """
        if not self.__req.closed:
            try:
                self.__req.send_json({'tag': 'exit'}, flags=zmq.NOBLOCK)
                self.__req.recv_json(flags=zmq.NOBLOCK)
            except zmq.error.Again:
                pass
            self.__req.close()

    def __try_recv_json(self):
        """Try to receive from the request socket, but guard for exceptions."""
        try:
            return self.__req.recv_json()
        except:
            self.__control_req.send_json({'tag': 'interrupt',
                                          'port': self.__port})
            self.__control_req.recv_json()
            self.__req.recv_json()
            raise


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
            fields = [u'{} = {}'.format(k, _CryptolModule.to_expr(v))
                      for k, v in pyval.items()]
            return u'{{{}}}'.format(', '.join(fields))
        # tuple -> tuple
        elif isinstance(pyval, tuple):
            elts = [_CryptolModule.to_expr(v) for v in pyval]
            return u'({})'.format(', '.join(elts))
        # list of length n containing a -> [n]a
        elif isinstance(pyval, list):
            elts = [_CryptolModule.to_expr(v) for v in pyval]
            return u'[{}]'.format(', '.join(elts))
        # BitVector of length n -> [n]
        elif isinstance(pyval, BitVector):
            return u'{:d} : [{}]'.format(int(pyval), pyval.length())
        else:
            # TODO: convert strings to ASCII?
            raise TypeError(
                'Unable to convert Python value into '
                'Cryptol expression: {!s}'.format(pyval))

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
    """Base class for errors arising from the Cryptol interpreter"""
    # TODO: add a class hierarchy to break down the different types of
    # Cryptol errors
    pass

class CryptolServerError(CryptolError):
    """An error starting or communicating with the Cryptol server executable"""
    pass

class ProverError(CryptolError):
    """An error arising from the prover configured for Cryptol"""
    pass

class PycryptolInternalError(Exception):
    """An internal error in pycryptol that indicates a bug

    This deliberately does not extend :class:`.CryptolError`, since it
    should not be expected during normal execution.

    """
    def __init__(self, msg):
        self.msg = msg
        super(PycryptolInternalError, self).__init__()

    def __str__(self):
        template = (
            u'Encountered an error in pycryptol:\n\n'
            '\t{0}\n\n'
            'Please report this as a bug at '
            'https://github.com/GaloisInc/pycryptol/issues'
        )
        return template.format(self.msg)

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
