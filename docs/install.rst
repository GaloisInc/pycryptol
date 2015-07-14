Getting Started
===============

.. Note::

   This guide is specific to the pre-release experimental state of
   this library. As the Python library becomes publicly available and
   the required server modifications are merged into the mainline of
   Cryptol, installation will be much more straightforward.

   Please report any difficulties you find with this library at the
   `issue tracker <https://github.com/GaloisInc/pycryptol/issues>`_.

To use pycryptol, both the `pycryptol
<https://github.com/GaloisInc/pycryptol>`_ Python library and the
``cryptol-server`` Haskell executable must be installed. This guide
assumes that you already have Python and `pip <https://pip.pypa.io/>`_
installed, and that you have a Haskell toolchain capable of building
`Cryptol <https://github.com/GaloisInc/cryptol>`_.

Installing the Python Library
-----------------------------

The Python library is most easily installed using pip::

  pip install git+ssh://git@github.com/GaloisInc/pycryptol.git \
      --allow-external BitVector \
      --allow-unverified BitVector

.. Note::

   The `BitVector
   <https://engineering.purdue.edu/kak/dist/BitVector-3.4.3.html>`_
   library used in pycryptol is hosted outside the usual PyPI
   repository, and so requires extra flags when installing.

On OS X and Windows, the ``pyzmq`` dependency should build and install
automatically. If the installation produces errors related to
``pyzmq``, though, you may need to install the developer versions of
the ZeroMQ library. For more, see the `pyzmq documentation
<https://github.com/zeromq/pyzmq/blob/master/README.md#building-and-installation>`_.

Installing the Cryptol Server
-----------------------------

This guide assumes that you are already able to build Cryptol from a
GitHub checkout; see the `Cryptol documentation
<https://github.com/GaloisInc/cryptol/blob/master/README.md#building-cryptol-from-source>`_
for instructions.

#. Check out the ``feature/cryptol-server`` branch from the Cryptol repository::

     $ git clone https://github.com/GaloisInc/cryptol.git
     ...
     $ cd cryptol
     $ git checkout feature/cryptol-server
     Branch feature/cryptol-server set up to track remote branch feature/cryptol-server from origin.
     Switched to a new branch 'feature/cryptol-server'

#. Build the Cryptol distribution::

     $ make dist
     ...

#. Extract the resulting ``.tar`` or ``.zip`` file to a location of
   your choice as you would with a normal Cryptol release.

#. Make sure your system ``PATH`` contains the location you extracted
   the distribution. You should be able to start the
   ``cryptol-server`` executable at your shell (you can shut the
   server down after testing by pressing ``Ctrl-C``)::

     $ cryptol-server
     [cryptol-server] coming online at tcp://127.0.0.1:5555

Testing your Installation
-------------------------

With the ``pycryptol`` library and the ``cryptol-server`` executable
installed, you can use the Python interpreter to test whether all of
the components were successfully installed. For example::

  $ python
  Python 2.7.9 (default, Feb 10 2015, 03:28:08)
  [GCC 4.2.1 Compatible Apple LLVM 6.0 (clang-600.0.56)] on darwin
  Type "help", "copyright", "credits" or "license" for more information.
  >>> import cryptol
  >>> cry = cryptol.Cryptol()
  >>> prelude = cry.prelude()
  >>> int(prelude.eval("1+1"))
  0