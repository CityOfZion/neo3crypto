.. image:: https://raw.githubusercontent.com/CityOfZion/visual-identity/develop/_CoZ%20Branding/_Logo/_Logo%20icon/_PNG%20200x178px/CoZ_Icon_DARKBLUE_200x178px.png
    :alt: CoZ logo


NEO3VM
------
C++ implementations of cryptographic functions used in the NEO3 Blockchain with bindings for Python 3.7 & 3.8.

The current version only supports EllipticCurve functions by wrapping `micro-ecc <https://github.com/kmackay/micro-ecc>`_)
and exposing helper classes. ``SECP256R1`` (a.k.a ``NIST256P``) and ``SECP256K1`` are the only curves exposed, but others can easily
be enabled if needed.

Installation
~~~~~~~~~~~~
::

    pip install neo3crypto

Or download the wheels from the Github releases page.

Windows users
=============
::

If installing fails with the error ``No Matching distribution found`` then upgrade your Python installation to use the latest post release version (i.e. ``3.8.8`` instead of ``3.8.0``)

Usage
~~~~~

::

    import hashlib
    import os
    from neo3crypto import ECCCurve, ECPoint, sign, verify


    curve = ECCCurve.SECP256R1
    private_key = os.urandom(32)
    public_key = ECPoint(private_key, curve)

    signature = sign(private_key, b'message', curve, hashlib.sha256)
    assert ecdsa.verify(signature, b'message', public_key, hashlib.sha256) == True

Any hashlib hashing function can be used. Further documentation on the classes can be queried from the extension module
using ``help(neo3crypto)``.

Building wheels
~~~~~~~~~~~~~~~
Make sure to have ``wheel`` and ``CMake`` installed. Then call ``python setup.py bdist_wheel``.
