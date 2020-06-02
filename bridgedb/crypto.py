# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2007-2017, The Tor Project, Inc.
#             (c) 2013-2017, Isis Lovecruft
#             (c) 2007-2017, all entities within the AUTHORS file
# :license: 3-clause BSD, see included LICENSE for information

"""This module contains general utilities for working with external
cryptographic tools and libraries, like OpenSSL. It also includes utilities for
creating callable HMAC functions, generating HMACs for data, and generating
and/or storing key material.

.. py:module:: bridgedb.crypto
   :synopsis: BridgeDB general cryptographic utilities.

::

   bridgedb.crypto
     |_getHMAC() - Compute an HMAC with some key for some data.
     |_getHMACFunc() - Get a callable for producing HMACs with the given key.
     |_getKey() - Load the master HMAC key from a file, or create a new one.
     |_getRSAKey() - Load an RSA key from a file, or create a new one.
     |_writeKeyToFile() - Write to a file readable only by the process owner.
     |
     \_SSLVerifyingContextFactory - OpenSSL.SSL.Context factory which verifies
        |                           certificate chains and matches hostnames.
        |_getContext() - Retrieve an SSL context configured for certificate
        |                verification.
        |_getHostnameFromURL() - Parses the hostname from the request URL.
        \_verifyHostname() - Check that the cert CN matches the request
                             hostname.
..
"""

from __future__ import absolute_import
from __future__ import unicode_literals

import hashlib
import hmac
import io
import logging
import os
import re
import urllib.parse

import OpenSSL

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from twisted.internet import ssl
from twisted.python.procutils import which


from service_identity.cryptography import verify_certificate_hostname
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from service_identity import VerificationError, CertificateError, SubjectAltNameWarning

#: The hash digest to use for HMACs.
DIGESTMOD = hashlib.sha1


class PKCS1PaddingError(Exception):
    """Raised when there is a problem adding or removing PKCS#1 padding."""

class RSAKeyGenerationError(Exception):
    """Raised when there was an error creating an RSA keypair."""


def writeKeyToFile(key, filename):
    """Write **key** to **filename**, with ``400`` octal permissions.

    If **filename** doesn't exist, it will be created. If it does exist
    already, and is writable by the owner of the current process, then it will
    be truncated to zero-length and overwritten.

    :param bytes key: A key (or some other private data) to write to
        **filename**.
    :param str filename: The path of the file to write to.
    :raises: Any exceptions which may occur.
    """
    logging.info("Writing key to file: %r" % filename)
    flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT | getattr(os, "O_BIN", 0)
    fd = os.open(filename, flags, 0o400)
    os.write(fd, key)
    os.fsync(fd)
    os.close(fd)

def getRSAKey(filename, bits=2048):
    """Load the RSA key stored in **filename**, or create and save a new key.

    >>> from bridgedb import crypto
    >>> keyfile = 'doctest_getRSAKey'
    >>> message = "The secret words are Squeamish Ossifrage."
    >>> keypair = crypto.getRSAKey(keyfile, bits=2048)
    >>> (secretkey, publickey) = keypair
    >>> encrypted = publickey.encrypt(message)
    >>> assert encrypted != message
    >>> decrypted = secretkey.decrypt(encrypted)
    >>> assert message == decrypted


    If **filename** already exists, it is assumed to contain a PEM-encoded RSA
    private key, which will be read from the file. (The parameters of a
    private RSA key contain the public exponent and public modulus, which
    together comprise the public key ― ergo having two separate keyfiles is
    assumed unnecessary.)

    If **filename** doesn't exist, a new RSA keypair will be created, and the
    private key will be stored in **filename**, using :func:`writeKeyToFile`.

    Once the private key is either loaded or created, the public key is
    extracted from it. Both keys are then input into PKCS#1 RSAES-OAEP cipher
    schemes (see `RFC 3447 §7.1`__) in order to introduce padding, and then
    returned.

    .. __: https://tools.ietf.org/html/rfc3447#section-7.1

    :param str filename: The filename to which the secret parameters of the
        RSA key are stored in.
    :param int bits: If no key is found within the file, create a new key with
        this bitlength and store it in **filename**.
    :rtype: tuple of ``Crypto.Cipher.PKCS1_OAEP.PKCS1OAEP_Cipher``
    :returns: A 2-tuple of ``(privatekey, publickey)``, which are PKCS#1
        RSAES-OAEP padded and encoded private and public keys, forming an RSA
        keypair.
    """
    filename = os.path.extsep.join([filename, 'sec'])
    keyfile = os.path.join(os.getcwd(), filename)

    try:
        fh = open(keyfile, 'rb')
    except IOError:
        logging.info("Generating %d-bit RSA keypair..." % bits)
        secretKey = RSA.generate(bits, e=65537)

        # Store a PEM copy of the secret key (which contains the parameters
        # necessary to create the corresponding public key):
        secretKeyPEM = secretKey.exportKey("PEM")
        writeKeyToFile(secretKeyPEM, keyfile)
    else:
        logging.info("Secret RSA keyfile %r found. Loading..." % filename)
        secretKey = RSA.importKey(fh.read())
        fh.close()

    publicKey = secretKey.publickey()

    # Add PKCS#1 OAEP padding to the secret and public keys:
    sk = PKCS1_OAEP.new(secretKey)
    pk = PKCS1_OAEP.new(publicKey)

    return (sk, pk)

def getKey(filename):
    """Load the master key stored in ``filename``, or create a new key.

    If ``filename`` does not exist, create a new 32-byte key and store it in
    ``filename``.

    >>> import os
    >>> from bridgedb import crypto
    >>> name = 'doctest_getKey'
    >>> os.path.exists(name)
    False
    >>> k1 = crypto.getKey(name)
    >>> os.path.exists(name)
    True
    >>> open(name).read() == k1
    True
    >>> k2 = crypto.getKey(name)
    >>> k1 == k2
    True

    :param string filename: The filename to store the secret key in.
    :rtype: bytes
    :returns: A byte string containing the secret key.
    """
    try:
        fh = open(filename, 'rb')
    except IOError:
        logging.debug("getKey(): Creating new secret key.")
        key = os.urandom(32)
        writeKeyToFile(key, filename)
    else:
        logging.debug("getKey(): Secret key file found. Loading...")
        key = fh.read()
        fh.close()
    return key

def getHMAC(key, value):
    """Return the HMAC of **value** using the **key**."""

    # normalize inputs to be bytes

    key = key.encode('utf-8') if isinstance(key, str) else key
    value = value.encode('utf-8') if isinstance(value, str) else value

    h = hmac.new(key, value, digestmod=DIGESTMOD)
    return h.digest()

def getHMACFunc(key, hex=True):
    """Return a function that computes the HMAC of its input using the **key**.

    :param bool hex: If True, the output of the function will be hex-encoded.
    :rtype: callable
    :returns: A function which can be uses to generate HMACs.
    """

    key = key.encode('utf-8') if isinstance(key, str) else key
    h = hmac.new(key, digestmod=DIGESTMOD)

    def hmac_fn(value):
        value = value.encode('utf-8') if isinstance(value, str) else value
        h_tmp = h.copy()
        h_tmp.update(value)
        if hex:
            return h_tmp.hexdigest()
        else:
            return h_tmp.digest()

    return hmac_fn

def removePKCS1Padding(message):
    """Remove PKCS#1 padding from a **message**.

    (PKCS#1 v1.0?  See :trac:`13042`.)

    Each block is 128 bytes total in size:

        * 2 bytes for the type info (``'\\x00\\x01'``)
        * 1 byte for the separator (``'\\x00'``)
        * variable length padding (``'\\xFF'``)
        * variable length for the **message**

    .. Note that the above strings are double escaped, due to the way that
       Sphinx renders escaped strings in docstrings.

    For more information on the structure of PKCS#1 padding, see :rfc:`2313`,
    particularly `the notes in §8.1`__.

    .. __: https://tools.ietf.org/html/rfc2313#section-8.1

    :param str message: A message which is PKCS#1 padded.
    :raises PKCS1PaddingError: if there is an issue parsing the **message**.
    :rtype: bytes
    :returns: The message without the PKCS#1 padding.
    """
    padding = b'\xFF'
    typeinfo = b'\x00\x01'
    separator = b'\x00'

    unpadded = None

    try:
        if message.index(typeinfo) != 0:
            raise PKCS1PaddingError("Couldn't find PKCS#1 identifier bytes!")
        start = message.index(separator, 2) + 1  # 2 bytes for the typeinfo,
                                                 # and 1 byte for the separator.
    except ValueError:
        raise PKCS1PaddingError("Couldn't find PKCS#1 separator byte!")
    else:
        unpadded = message[start:]

    return unpadded


class SSLVerifyingContextFactory(ssl.CertificateOptions):
    """``OpenSSL.SSL.Context`` factory which does full certificate-chain and
    hostname verfication.
    """
    isClient = True

    def __init__(self, url, **kwargs):
        """Create a client-side verifying SSL Context factory.

        To pass acceptable certificates for a server which does
        client-authentication checks: initialise with a ``caCerts=[]`` keyword
        argument, which should be a list of ``OpenSSL.crypto.X509`` instances
        (one for each peer certificate to add to the store), and set
        ``SSLVerifyingContextFactory.isClient=False``.

        :param str url: The URL being requested by an
            :api:`twisted.web.client.Agent`.
        :param bool isClient: True if we're being used in a client
            implementation; False if we're a server.
        """
        self.hostname = self.getHostnameFromURL(url)

        # ``verify`` here refers to server-side verification of certificates
        # presented by a client:
        self.verify = False if self.isClient else True
        super(SSLVerifyingContextFactory, self).__init__(verify=self.verify,
                                                         fixBrokenPeers=True,
                                                         **kwargs)

    def getContext(self, hostname=None, port=None):
        """Retrieve a configured ``OpenSSL.SSL.Context``.

        Any certificates in the ``caCerts`` list given during initialisation
        are added to the ``Context``'s certificate store.

        The **hostname** and **port** arguments seem unused, but they are
        required due to some Twisted and pyOpenSSL internals. See
        :api:`twisted.web.client.Agent._wrapContextFactory`.

        :rtype: ``OpenSSL.SSL.Context``
        :returns: An SSL Context which verifies certificates.
        """
        ctx = super(SSLVerifyingContextFactory, self).getContext()
        store = ctx.get_cert_store()
        verifyOptions = OpenSSL.SSL.VERIFY_PEER
        ctx.set_verify(verifyOptions, self.verifyHostname)
        return ctx

    def getHostnameFromURL(self, url):
        """Parse the hostname from the originally requested URL.

        :param str url: The URL being requested by an
            :api:`twisted.web.client.Agent`.
        :rtype: str
        :returns: The full hostname (including any subdomains).
        """

        hostname = urllib.parse.urlparse(url).netloc
        logging.debug("Parsed hostname %r for cert CN matching." % hostname)
        return hostname

    def verifyHostname(self, connection, x509, errnum, depth, okay):
        """Callback method for additional SSL certificate validation.

        If the certificate is signed by a valid CA, and the chain is valid,
        verify that the level 0 certificate has a subject common name which is
        valid for the hostname of the originally requested URL.

        :param connection: An ``OpenSSL.SSL.Connection``.
        :param x509: An ``OpenSSL.crypto.X509`` object.
        :param errnum: A pyOpenSSL error number. See that project's docs.
        :param depth: The depth which the current certificate is at in the
            certificate chain.
        :param bool okay: True if all the pyOpenSSL default checks on the
            certificate passed. False otherwise.
        """
        commonName = x509.get_subject().commonName
        logging.debug("Received cert at level %d: '%s'" % (depth, commonName))

        x509 = x509.to_cryptography()
        # We only want to verify that the hostname matches for the level 0
        # certificate:
        if okay and (depth == 0):
            try:
                verify_certificate_hostname(x509,self.hostname)
                logging.debug("Valid certificate subject CN for '%s': '%s'"
                          % (self.hostname, commonName))
                return True
            except VerificationError:
                logging.warn("Invalid certificate subject CN for '%s': '%s'"
                                % (self.hostname, commonName))
                return False
            except CertificateError:
                logging.warn("Certificate contains invalid or unexpected data")
                return False
            except SubjectAltNameWarning:
                logging.warn("Certificate contains no SAN, fallback to common name")
                cn = commonName.replace('*', '.*')
                hostnamesMatch = re.search(cn, self.hostname)
                if not hostnamesMatch:
                    return False
                return True
