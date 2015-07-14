"""A setuptools based setup module.
See:
https://packaging.python.org/en/latest/distributing.html
https://github.com/pypa/sampleproject
"""

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the relevant file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='pycryptol',

    # Versions should comply with PEP440.  For a discussion on single-sourcing
    # the version across setup.py and the project code, see
    # https://packaging.python.org/en/latest/single_source_version.html
    version='1.0.0a1',

    description='Python bindings to the Cryptol programming language',
    long_description=long_description,

    # The project's main homepage.
    url='https://github.com/GaloisInc/pycryptol',

    # Author details
    author='Galois, Inc.',
    author_email='cryptol@galois.com',

    # Choose your license
    license='BSD3',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 3 - Alpha',

        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2.7',
    ],

    # What does your project relate to?
    keywords='cryptography cryptol',

    # You can just specify the packages manually here if your project is
    # simple. Or you can use find_packages().
    packages=find_packages(exclude=['contrib', 'docs', 'tests*']),

    # List run-time dependencies here.  These will be installed by pip when
    # your project is installed. For an analysis of "install_requires" vs pip's
    # requirements files see:
    # https://packaging.python.org/en/latest/requirements.html
    install_requires=['BitVector', 'enum34', 'pyzmq'],
)
