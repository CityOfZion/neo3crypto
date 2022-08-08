.. image:: https://raw.githubusercontent.com/CityOfZion/visual-identity/develop/_CoZ%20Branding/_Logo/_Logo%20icon/_PNG%20200x178px/CoZ_Icon_DARKBLUE_200x178px.png
    :alt: CoZ logo


NEO3VM
------
C++ implementations of cryptographic functions used in the NEO3 Blockchain with bindings for Python 3.8, 3.9 & 3.10.

The current version supports `mmh3` and EllipticCurve functions by wrapping (part of `smhasher <https://github.com/aappleby/smhasher>`_ and `micro-ecc <https://github.com/kmackay/micro-ecc>`_)
and exposing helper classes. ``SECP256R1`` (a.k.a ``NIST256P``) and ``SECP256K1`` are the only curves exposed, but others can easily
be enabled if needed.

Installation
~~~~~~~~~~~~
::

    pip install neo3crypto

Or download the wheels from the Github releases page.

Usage
~~~~~

::

    import hashlib
    import os
    from neo3crypto import ECCCurve, ECPoint, sign, verify, mmh3_hash_bytes, mmh3_hash


    curve = ECCCurve.SECP256R1
    private_key = os.urandom(32)
    public_key = ECPoint(private_key, curve)

    signature = sign(private_key, b'message', curve, hashlib.sha256)
    assert ecdsa.verify(signature, b'message', public_key, hashlib.sha256) == True

    assert mmh3_hash("foo", signed=False) == 4138058784
    assert bytes.fromhex("0bc59d0ad25fde2982ed65af61227a0e") == mmh3_hash_bytes("hello", 123)

Any hashlib hashing function can be used. Further documentation on the classes can be queried from the extension module
using ``help(neo3crypto)``.

Building wheels
~~~~~~~~~~~~~~~
Make sure to have ``wheel`` and ``CMake`` installed. Then call ``python setup.py bdist_wheel``.