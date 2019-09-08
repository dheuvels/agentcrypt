# -*- coding: utf-8 -*-

from __future__ import absolute_import
from future.utils import raise_from

import base64
import binascii
from distutils.version import StrictVersion
from io import BytesIO
import os
import sys

from agentcrypt import __version__, COMPAT_VERSION
from .exceptions import AgentCryptException, NoContainerException
from .crypto import Cipher, SSHAgent
from .py2compat import is_file, try_truncate, try_bytes


class Container(BytesIO):
    """The public interface for encrypting and decrypting data.
    :class:`Container` objects represent files or streams of encrypted data.
    Instances of this class should be created with the help of the following static methods

    - :func:`create`: Store encrypted data in a new container.
    - :func:`load`: Load or modify an existing container.

    :class:`Container` inherits from :class:`io.BytesIO`, thus it can be used as a stream.
    Use the inherited methode :func:`getvalue` to access the contained data in decrypted form.
    """

    def __init__(self, io_handle, ssh_key, cipher, nonce, salt, data=None, create_path=None):
        self.io_handle = io_handle
        self.ssh_key = ssh_key
        self.cipher = cipher
        self.nonce = nonce
        self.salt = salt

        self._changes = True if data and create_path else False
        self._create_path = create_path

        super(Container, self).__init__(initial_bytes=try_bytes(data))
        super(Container, self).seek(0, os.SEEK_END)

    @classmethod
    def create(cls, write_target, ssh_key_fp=None, cipher_name=None, data=None):
        """Creates a new container.

        :param write_target: Either a filehandle or a path to the target container as string.
                             If an instance of :class:`io.IOBase` is detected (`file` instance in Python2) the parameter
                             will be treated as handle. Otherwise it is interpreted as path and used as the first
                             parameter to ``open()``, to get a filehandle.
        :param ssh_key_fp: The SHA256 fingerprint of the key to use for encryption. If set to ``None``, the first key
                           found in the key-agent is used (use ``ssh-add -l -E sha256`` to get valid fingerprints).
        :param cipher_name: The symmetric cipher to use. Must be one of the values from the cipher names published by
                            :class:`.crypto.Cipher`. Use `None` to pick the strongest available cipher.
        :param data: The initial data to write to the container. Additional data can be added with :func:`write` or
                     :func:`writelines` after the container has been created.
        :return: :class:`Container` instance
        """
        path=None
        if is_file(write_target):
            io_handle = write_target
        else:
            path = write_target
            try:
                io_handle = open(path, "w")
            except IOError as ioe:
                raise_from(AgentCryptException("Cannot write to '{}'.".format(write_target)), ioe)

        ssh_key = SSHAgent.get_key(ssh_key_fp)
        if not ssh_key:
            raise AgentCryptException("Key with fingerprint '{}' not found in SSH agent.".format(ssh_key_fp))
        cipher = Cipher(cipher_name)

        return cls(io_handle, ssh_key, cipher, cipher.get_nonce, cipher.get_salt, data, create_path=path)

    @classmethod
    def load(cls, rw_target):
        """Loads an existing container.

        :param rw_target: A path (string) or a filehandle (:class:`io.IOBase` in Python3, `file` instance in Python2)
                          to load from.

        :return: :class:`Container` instance

        Use the inherited methode :func:`getvalue` to access the contained data in decrypted form.
        """
        if is_file(rw_target):
            io_handle = rw_target
        else:
            try:
                io_handle = open(rw_target, "r+")
            except IOError as ioe:
                raise_from(AgentCryptException("Cannot open '{}' in read-write mode.".format(rw_target)), ioe)

        hname = io_handle.name
        try:
            headers = Container._read_headers(io_handle)
            data_enc = base64.b64decode(io_handle.read())
        except IOError as ioe:
            raise_from(AgentCryptException("Cannot read from input stream '{}'.".format(hname)), ioe)
        except (binascii.Error, TypeError) as err:
            raise_from(AgentCryptException("Cannot read Base64 data part from input stream '{}'.".format(hname)), err)

        ssh_key = SSHAgent.get_key(headers.ssh_key_fp)
        if not ssh_key:
            raise AgentCryptException("SSH key '{}' is required for decrypting input stream '{}', but not in SSH agent."
                                      .format(headers.ssh_key_fp, hname))
        ssh_sigb = ssh_key.get_ssh_signature_blob(headers.nonce)

        cipher = Cipher(headers.cipher_name)
        data = cipher.decrypt(data_enc, ssh_sigb, headers.salt)

        return cls(io_handle, ssh_key, cipher, headers.nonce, headers.salt, data)

    def save(self):
        """Alias for `close()`.
        """
        return self.close()

    def rekey(self, cipher_name=None):
        """
        Creates a new nonce, optionally with a different cipher an marks the container as `modified`, so that it will be
        written, when :func:`flush` is called.
        """
        if cipher_name:
            self.cipher = Cipher(cipher_name)
        self.nonce = self.cipher.get_nonce
        self.salt = self.cipher.get_salt
        self._changes = True

    def flush(self):
        """
        Writes the container if it was modified.
        The container is modified, if either..

        - It was instantiated with the :func:`create` method and a ``data`` parameter that was not empty.
        - Any of the methods has been called, that modify the content (:func:`write`, :func:`rekey`, :func:`clear`, ..).
        """
        if not self._changes:
            return

        ssh_sigb = self.ssh_key.get_ssh_signature_blob(self.nonce)
        data_enc = self.cipher.encrypt(self.getvalue(), ssh_sigb, self.salt)

        headers = ContainerHeaders(self.ssh_key.get_sha256_fingerprint(), self.cipher.cipher_name, self.nonce, self.salt)
        try:
            try_truncate(self.io_handle)
            self.io_handle.write(str(headers))
            self.io_handle.write(base64.b64encode(data_enc).decode())
            self.io_handle.flush()
        except IOError as ioe:
            raise_from(AgentCryptException("Cannot write to output stream '{}'.".format(self.io_handle.name)), ioe)

        self._changes = False

    def close(self):
        """
        Writes the container, if it was modified and closes it.
        There is a cleanup logic, that will delete empty containers, if all of the following conditions hold true:

        - The container is new and empty (method :func:`create` was called with empty ``data`` parameter).
        - A new file was created for it (parameter ``write_target`` was not an existing filehandle).
        - The container has not been modified since it was created.
        """
        if not self.closed:
            if self._changes:
                self.flush()
            elif self._create_path:
                os.unlink(self._create_path)  # Don't keep newly created containers without content.

            self.io_handle.close()
        super(Container, self).close()

    def write(self, b):
        super(Container, self).write(try_bytes(b))
        self._changes = True

    def writelines(self, lines):
        blines = list(map(lambda line: try_bytes(line), lines))
        super(Container, self).writelines(blines)
        self._changes = True

    def truncate(self, size=None):
        super(Container, self).truncate(size)
        self._changes = True

    def clear(self):
        """
        Convenience method for clearing the container contents. Same as ``truncate(0)`` and ``seek(0)``.
        """
        self.truncate(0)
        self.seek(0)

    @classmethod
    def _read_headers(cls, io_hndl):
        hname = io_hndl.name
        line_cnt = 1

        line = io_hndl.readline(128)
        if line[0:len(ContainerHeaders.HEADLINE)] != ContainerHeaders.HEADLINE:
            raise NoContainerException("Input stream '{}' is not an AgentCrypt container. Expected header '{}'."
                                       .format(hname, ContainerHeaders.HEADLINE.rstrip()))
        try:
            file_ver = StrictVersion(line[len(ContainerHeaders.HEADLINE):].rstrip())
            if file_ver > StrictVersion(COMPAT_VERSION):
                raise AgentCryptException("Input stream '{}' has unsupported version {}."
                                          .format(hname, line_cnt, file_ver))
        except ValueError as ve:
            raise_from(AgentCryptException("Input stream '{}' line {:d}: Malformed version string."
                                           .format(hname, line_cnt)), ve)

        headers = ContainerHeaders()
        for caption, set_func in [(ContainerHeaders.SSH_KEY_FP, headers.set_ssh_key_fp),
                                  (ContainerHeaders.CIPHER, headers.set_cipher_name),
                                  (ContainerHeaders.NONCE, headers.set_nonce),
                                  (ContainerHeaders.SALT, headers.set_salt)]:
            line_cnt += 1
            line = io_hndl.readline()
            if line[0:len(caption)] == caption:
                value = line[len(caption):].rstrip()
                try:
                    set_func(value)
                except Exception as ex:
                    raise_from(AgentCryptException("Input stream '{}' line {:d}: Invalid value '{}'."
                                                   .format(hname, line_cnt, value)), ex)
            else:
                raise AgentCryptException("Input stream '{}' line {:d}: Expected '{}<data>'."
                                          .format(hname, line_cnt, caption))

        return headers


class ContainerHeaders(object):
    HEADLINE = "AgentCrypt: "
    SSH_KEY_FP = "SSHKeyFP: "
    CIPHER = "Cipher: "
    NONCE = "Nonce: "
    SALT = "Salt: "

    def __init__(self, ssh_key_fp=None, cipher_name=None, nonce=None, salt=None):
        self.ssh_key_fp = ssh_key_fp
        self.cipher_name = cipher_name
        self.nonce = nonce
        self.salt = salt

    def set_ssh_key_fp(self, ssh_key_fp):
        self.ssh_key_fp = ssh_key_fp

    def set_cipher_name(self, cipher_name):
        self.cipher_name = cipher_name

    def set_nonce(self, nonce_b64):
        self.nonce = base64.b64decode(nonce_b64)

    def set_salt(self, salt_b64):
        self.salt = base64.b64decode(salt_b64)

    def __str__(self):
        header_lines = [
            ContainerHeaders.HEADLINE + __version__,
            ContainerHeaders.SSH_KEY_FP + self.ssh_key_fp.decode(),
            ContainerHeaders.CIPHER + self.cipher_name,
            ContainerHeaders.NONCE + base64.b64encode(self.nonce).decode(),
            ContainerHeaders.SALT + base64.b64encode(self.salt).decode()
        ]
        return "\n".join(header_lines) + "\n"


if __name__ == "__main__":
    if 1 < len(sys.argv) < 4:
        if sys.argv[1] == "enc":
            fp = sys.argv[2] if len(sys.argv) == 3 else None
            with Container.create(sys.stdout, ssh_key_fp=fp) as cntr:
                for line in sys.stdin:
                    cntr.write(line)
            sys.exit(0)
        elif sys.argv[1] == "dec":
            with Container.load(sys.stdin) as cntr:
                print(cntr.getvalue().decode())
            sys.exit(0)
    print("""
Syntax:
  {0} enc [fingerprint] < data.txt > container.enc
  {0} dec < container.enc
          """.format(os.path.basename(sys.argv[0])))
    sys.exit(1)
