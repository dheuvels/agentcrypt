# -*- coding: utf-8 -*-

from __future__ import absolute_import
from future.utils import raise_from

import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import ciphers, hashes, padding
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from hashlib import sha256
import os
import paramiko
from paramiko.py3compat import b
from paramiko import SSHException
import struct

from .exceptions import AgentCryptException
from .py2compat import try_bytes


class AgentKey(paramiko.AgentKey):
    """ Specialization of `paramiko.agent.AgentKey`_ with a few additions for our purposes.

    .. _`paramiko.agent.AgentKey`: http://docs.paramiko.org/en/2.4/api/agent.html#paramiko.agent.AgentKey
    """

    _SUPPORTED_KEY_TYPES = ['ssh-rsa', 'ssh-ed25519']

    def __init__(self, agent, agent_key):
        super(AgentKey, self).__init__(agent, agent_key.asbytes())

    def get_sha256_fingerprint(self):
        """
        SHA256 fingerprint extension from `pull request 1103`_.

        .. _`pull request 1103`: https://github.com/paramiko/paramiko/pull/1103/commits/8e0b7ef85fc72d844dee80688060001a3fba8ad0
        """
        return base64.b64encode(b(sha256(self.asbytes()).digest()))[:-1]

    def get_ssh_signature_blob(self, data):
        """ Signs ``data`` and returns the signature as `bytes`.

        :param data: The `bytes` object to be signed.
        :return: The signature part of the resulting `SSH_AGENT_SIGN_RESPONSE` message as described in the RFCs
                 referenced by the `SSH Agent Protocol draft`_.

        .. _`SSH Agent Protocol draft`: https://tools.ietf.org/id/draft-miller-ssh-agent-00.html#rfc.section.4.5.
        """
        try:
            sig_msg = super(AgentKey, self).sign_ssh_data(data)
        except SSHException as sshe:
            raise_from(AgentCryptException("Failed access key '{}'. You probably added it with the confirmation option "
                                           "(ssh-add -c ..) and did not confirm. (Did you install 'ssh-askpass'?)"
                                           .format(self.get_sha256_fingerprint().decode())), sshe)

        msg_parts = []
        try:
            for loop in range(0, 2):
                plen = struct.unpack('>I', sig_msg[:4])[0]
                msg_parts.append(sig_msg[4:(plen+4)])
                sig_msg = sig_msg[(plen+4):]
        except struct.error as se:
            raise_from(AgentCryptException("Failed to unpack SSH_AGENT_SIGN_RESPONSE from agent."), se)

        # Some sanity checks on the signature message.
        if len(msg_parts) != 2:
            raise AgentCryptException("Got unexpected SSH_AGENT_SIGN_RESPONSE message from agent "
                                      "({:d} message parts instead of 2).".format(len(msg_parts)))

        sig_format = (msg_parts[0]).decode(errors='replace')
        sig_blob = msg_parts[1]

        if sig_format not in AgentKey._SUPPORTED_KEY_TYPES:
            raise AgentCryptException("Unsupported '{}' key signature in SSH_AGENT_SIGN_RESPONSE response."
                                      " Only the following key types are supported: '{}'"
                                      .format(sig_format, "', '".join(AgentKey._SUPPORTED_KEY_TYPES)))

        return sig_blob


class SSHAgent(paramiko.Agent):
    """ Specialization of `paramiko.agent.Agent`_ which uses :class:`crypto.AgentKey` objects internally.

    .. _`paramiko.agent.Agent`: http://docs.paramiko.org/en/2.4/api/agent.html#paramiko.agent.Agent
    """

    __instance = None

    def __init__(self):
        try:
            super(SSHAgent, self).__init__()
            self.ac_keys = list(map(lambda key: AgentKey(self, key), super(SSHAgent, self).get_keys()))

            if not self.ac_keys:
                raise AgentCryptException("No keys found in SSH agent.")

        except SSHException as sshe:
            raise_from(AgentCryptException("Failed to connect to SSH agent."), sshe)

    def __del__(self):
        super(SSHAgent, self).close()  # No other reasonable way than __del__(), to ensure close() is called.

    @classmethod
    def get_key(cls, key_fp=None):
        """
        Searches for the specified key in the agent. Creates a new instance of :class:`SSHAgent`, if necessary
        (singleton logic).

        :param key_fp: The SHA256 fingerprint of the key to search for. If ``None``, the first key is returned.
        :return: :class:`crypto.AgentKey` instance, if a key was found, or ``None`` if nothing was found.
        """
        if not cls.__instance:
            cls.__instance = SSHAgent()
        self = cls.__instance

        for key in self.ac_keys:
            if not key_fp or key.get_sha256_fingerprint() == try_bytes(key_fp):
                return key

        return None


class Cipher(object):
    """
    Provides symmetric encryption with the help of the `pyca/cryptography`_ library.

    .. _`pyca/cryptography`: https://cryptography.io
    """

    # As a loose convention `len` is the name for the length in bytes and `size` for the size in bits in this class.
    NONCE_LEN = 64
    SALT_LEN = 16

    AES_256_CBC = "AES_256_CBC"
    """ Cipher name. """
    AES_128_CBC = "AES_128_CBC"
    """ Cipher name. """
    DES_EDE3_CBC = "DES_EDE3_CBC"
    """ Cipher name. """
    Blowfish_CBC = "Blowfish_CBC"
    """ Cipher name. """

    def __init__(self, cipher_name=None):
        """Creates a new instance that uses the selected cipher.

        :param cipher_name: One of the cipher names exported by the static members above.
        :return: :class:`crypto.Cipher` instance.
        """

        cipher_name = cipher_name if cipher_name else Cipher.AES_256_CBC
        if cipher_name == Cipher.AES_256_CBC:
            self.algorithm = algorithms.AES
            self.block_size = algorithms.AES.block_size
            self.key_size = 256
        # Ciphers for converting legacy containers only. New ones should always be created as AES_256_CBC.
        elif cipher_name == Cipher.AES_128_CBC:
            self.algorithm = algorithms.AES
            self.block_size = algorithms.AES.block_size
            self.key_size = 128
        elif cipher_name == Cipher.DES_EDE3_CBC:
            self.algorithm = algorithms.TripleDES
            self.block_size = algorithms.TripleDES.block_size
            self.key_size = 192
        elif cipher_name == Cipher.Blowfish_CBC:
            self.algorithm = algorithms.Blowfish
            self.block_size = algorithms.Blowfish.block_size
            # Up to 448, but 128 were chosen one day, because it's considered strong and makes it testable with OpenSSL.
            self.key_size = 128
        else:
            raise AgentCryptException("Unsupported cipher '{}'.".format(cipher_name))
        self.cipher_name = cipher_name

    @property
    def get_nonce(self):
        # Convenience method to get a nonce with the preferred length.
        return os.urandom(Cipher.NONCE_LEN)

    @property
    def get_salt(self):
        # Convenience method to get a salt with the preferred length.
        return os.urandom(Cipher.SALT_LEN)

    @staticmethod
    def get_kdf(salt, key_size):
        """
        Returns the preferred Key Derivation Function (KDF) to be used for deriving the secret key from the signature
        returned by :func:`AgentKey.get_ssh_signature_blob`.

        :return: `PBKDF2HMAC`_ instance.

        This is the place to put another KDF, if preferred. An SCrypt example is provided in the code.
        BCrypt would add dependencies, that's why there is no code for it, but it can be added quiet simply.

        .. _`PBKDF2HMAC`: https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC
        """
        #return Scrypt(salt=salt, length=key_size // 8, n=2**14, r=8, p=1, backend=default_backend())
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(), salt=salt, length=key_size // 8, iterations=100000, backend=default_backend()
        )

    def encrypt(self, data, password, salt):
        """Encrypt data.

        :param data: Cleartext data to encrypt.
        :param password: The password (will be fed to the KDF in use).
        :param salt: The salt (will be fed to the KDF in use).
        :return: `bytes` object with encrypted data.
        """
        data = try_bytes(data)

        kdf = self.get_kdf(salt, self.key_size)
        key = kdf.derive(password)

        iv = os.urandom(self.block_size // 8)
        encryptor = (ciphers.Cipher(self.algorithm(key), modes.CBC(iv), backend=default_backend())).encryptor()

        padder = padding.PKCS7(self.block_size).padder()
        data = padder.update(data) + padder.finalize()
        return iv + encryptor.update(data) + encryptor.finalize()

    def decrypt(self, data_enc, password, salt):
        """Decrypt data.

        :param data: `bytes` object with encrypted data.
        :param password: The password (will be fed to the KDF in use).
        :param salt: The salt (will be fed to the KDF in use).
        :return: `bytes` object with cleartext data.
        """
        kdf = self.get_kdf(salt, self.key_size)
        key = kdf.derive(password)

        iv_bytes = self.block_size // 8
        iv = data_enc[0:iv_bytes]
        data_enc = data_enc[iv_bytes:]

        unpadder = padding.PKCS7(self.block_size).unpadder()
        decryptor = (ciphers.Cipher(self.algorithm(key), modes.CBC(iv), backend=default_backend())).decryptor()

        try:
            data = decryptor.update(data_enc) + decryptor.finalize()
            return unpadder.update(data) + unpadder.finalize()
        except (ValueError, TypeError):
            # No padding oracle scenario in our usecase, but probably a good habit not to raise with root cause.
            raise_from(AgentCryptException("Decryption failed."), AgentCryptException("*redacted*"))
