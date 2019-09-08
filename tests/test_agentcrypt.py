#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import base64
from binascii import hexlify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import algorithms, modes
import glob
from hashlib import sha256
import os
import paramiko
import paramiko.ed25519key
from paramiko.py3compat import b
import random
import re
import string
import subprocess
import unittest
import sys

from agentcrypt.exceptions import AgentCryptException
from agentcrypt.io import Container
from agentcrypt.crypto import Cipher


# Generate text without requiring fortunes or py-lorem.
def _lorem(len=16):
    return ("".join([random.choice(string.ascii_letters) for idx in range(len)])).encode()


def _sha256_fingerprint(key_obj):
    return base64.b64encode(b(sha256(key_obj.asbytes()).digest()))[:-1]


class SymmetricCipherTests(unittest.TestCase):
    OPENSSL_CIPHERS = {
        Cipher.AES_256_CBC: {'name': '-aes-256-cbc', 'key_size': 256, 'block_size': 128},
        Cipher.AES_128_CBC: {'name': '-aes-128-cbc', 'key_size': 128, 'block_size': 128},
        Cipher.DES_EDE3_CBC: {'name': '-des-ede3-cbc', 'key_size': 192, 'block_size': 64},
        Cipher.Blowfish_CBC: {'name': '-bf-cbc', 'key_size': 128, 'block_size': 64}
    }

    @staticmethod
    def _call_openssl(data, cipher, key, iv):
        args = ["openssl", "enc", "-e", cipher, "-base64", "-K", hexlify(key), "-iv", hexlify(iv)]
        p_hndl = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p_out = p_hndl.communicate(data)[0]
        return iv + base64.b64decode(p_out.rstrip())

    def test_00_decrypt_from_openssl(self):
        """
        Basic test of the symmetric ciphers: Take OpenSSL as reference and try to decrypt ciphertext made with it.
        """
        data_orig = _lorem()

        for our_cipher_name, ossl_cipher_equiv in SymmetricCipherTests.OPENSSL_CIPHERS.items():
            salt = os.urandom(Cipher.SALT_LEN)
            passwd = _lorem()

            key = Cipher.get_kdf(salt, ossl_cipher_equiv['key_size']).derive(passwd)
            iv = os.urandom(ossl_cipher_equiv['block_size'] // 8)
            data_enc_ossl = self._call_openssl(data_orig, ossl_cipher_equiv['name'], key, iv)

            data_decrypt = Cipher(our_cipher_name).decrypt(data_enc_ossl, passwd, salt)
            self.assertEqual(data_orig, data_decrypt)

    def test_01_padding_error_simulation(self):
        """
        Check the reactions to wrong passwords and paddings.
        """
        data_orig = b'd' * 32  # With AES+PKCS7 this gets us 2 encrypted blocks + 1 padding-only block full of 0x0f.
        passwd = b'hush hush'
        salt = b'chocolate salty balls'

        cipher = Cipher(Cipher.AES_256_CBC)
        data_enc = cipher.encrypt(data_orig, passwd, salt)

        # First of all, let's make sure decryption works.
        data_decrypt = cipher.decrypt(data_enc, passwd, salt)
        self.assertEqual(data_orig, data_decrypt)

        # Now test, if decryption with a wrong password raises the expected exception.
        with self.assertRaises(AgentCryptException) as assert_ctx:
            cipher.decrypt(data_enc, passwd + b'whoops', salt)
        # Decryption should not provide a root cause.
        self.assertEqual(str(assert_ctx.exception.__cause__), "*redacted*")

        # We know that the last block is padding only. Changing the last byte of it clutters up the padding block.
        buffer = bytearray(data_enc)
        buffer[-1] = buffer[-1] + 1
        data_enc_forged = bytes(buffer)

        # Now decryption should fail again, but due to a padding error.
        with self.assertRaises(AgentCryptException) as assert_ctx:
            cipher.decrypt(bytes(data_enc_forged), passwd, salt)
        # Padding error should not be distinguishable from a wrong password.
        self.assertEqual(str(assert_ctx.exception.__cause__), "*redacted*")

        # Sanity check: Make sure it was really the padding that was wrong and we can still decrypt that data blocks.
        iv = data_enc_forged[0:16]
        data_enc = data_enc_forged[16:]
        # Decryption without unpadding..
        key = Cipher.get_kdf(salt, 256).derive(passwd)
        decryptor = (ciphers.Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())).decryptor()
        data_decrypt_padded = decryptor.update(data_enc) + decryptor.finalize()
        # ..should match the original text.
        self.assertEqual(data_decrypt_padded[0:32], data_orig)


class AgentEncryptionTests(unittest.TestCase):
    SSH_TEST_KEYS = {
        'rsa_1024': {'loader': paramiko.RSAKey, 'type': "rsa", 'bytes': "1024"},
        'rsa_2048': {'loader': paramiko.RSAKey, 'type': "rsa", 'bytes': "2048"},
        'rsa_4096': {'loader': paramiko.RSAKey, 'type': "rsa", 'bytes': "4096"},
        'ed25519': {'loader': paramiko.ed25519key.Ed25519Key, 'type': 'ed25519', 'bytes': None},
    }

    @classmethod
    def setUpClass(cls):
        cls.agent_spawned = False
        cls.loaded_keys = []
        cls.fp_by_cntr_path = {}

        tmp_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), "temp")

        if os.path.isdir(tmp_dir):
            for path in glob.glob(tmp_dir + "/*"):
                os.unlink(path)
        else:
            os.mkdir(tmp_dir)
        cls.tmp_dir = tmp_dir

        key_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), "keys")
        for key_name in AgentEncryptionTests.SSH_TEST_KEYS:
            if not os.path.isdir(key_dir):
                os.mkdir(key_dir)

            key_path = os.path.join(key_dir, key_name)
            if not os.path.isfile(key_path):
                key_type = AgentEncryptionTests.SSH_TEST_KEYS[key_name]['type']
                key_bytes = AgentEncryptionTests.SSH_TEST_KEYS[key_name]['bytes']
                subprocess_params = [
                    "ssh-keygen",
                     "-t", key_type,
                     "-m", "RFC4716",
                     "-N", "",
                     "-C", "{}-{}".format(key_type, key_bytes),
                     "-f", key_path
                ]
                if key_bytes:
                    subprocess_params.append("-b", key_bytes)
                subprocess.call(subprocess_params)

        agent = paramiko.Agent()
        keys = agent.get_keys()

        if not keys and agent._conn is None:
            print("No ssh-agent found. Trying to start it at runtime.", file=sys.stderr)
            # Kind of best effort what follows.

            p_hndl = subprocess.Popen(["ssh-agent", "-c"], stdout=subprocess.PIPE)
            p_out = p_hndl.stdout
            re_pat = re.compile('^setenv ([A-Z_]+) (.+);')
            while True:
                line = p_out.readline().decode()
                if not line:
                    break
                match = re_pat.match(line)
                if match:
                    # Set the environment variables, so that paramiko finds the agent socket.
                    env_var = match.group(1)
                    env_val = match.group(2)
                    os.environ[env_var] = env_val
            p_hndl.communicate()

            agent = paramiko.Agent()
            cls.agent_spawned = True

        for filename in os.listdir(key_dir):
            if filename not in AgentEncryptionTests.SSH_TEST_KEYS:
                continue

            found_in_agent = False
            key_path = os.path.join(key_dir, filename)
            cntr_path = os.path.join(tmp_dir, "container_" + filename)

            for agent_key in agent.get_keys():
                file_key = AgentEncryptionTests.SSH_TEST_KEYS[filename]['loader'].from_private_key_file(key_path)
                file_key_fp = _sha256_fingerprint(file_key)

                if file_key_fp == _sha256_fingerprint(agent_key):
                    found_in_agent = True
                    break

            if not found_in_agent:
                os.chmod(key_path, 0o400)  # Make sure the permissions do not stop ssh-add the keys from loading.
                subprocess.check_call(["ssh-add", key_path])
                cls.loaded_keys.append(key_path)

            cls.fp_by_cntr_path[cntr_path] = file_key_fp

        cls.agent = agent

    @classmethod
    def tearDownClass(cls):
        cls.agent.close()
        if cls.agent_spawned:
            print("Bringing down ssh-agent.", file=sys.stderr)
            subprocess.check_call(["ssh-agent", "-k"], stdout=subprocess.PIPE)
        else:
            for key_path in cls.loaded_keys:
                subprocess.check_call(["ssh-add", "-d", key_path])
        for path in glob.glob(cls.tmp_dir + "/*"):
            os.unlink(path)

    def test_00_setup_complete(self):
        self.assertGreater(len(self.fp_by_cntr_path), 0)

    def test_01_container_file_interface_initial_data(self):
        data_orig_by_cntr_path = {}

        for cntr_path in self.fp_by_cntr_path:
            data_orig = _lorem()
            data_orig_by_cntr_path[cntr_path] = data_orig

            with Container.create(cntr_path, ssh_key_fp=self.fp_by_cntr_path[cntr_path], data=data_orig) as cntr:
                self.assertIsInstance(cntr, Container)

        for cntr_path in self.fp_by_cntr_path:
            cntr = Container.load(cntr_path)
            self.assertEqual(data_orig_by_cntr_path[cntr_path], cntr.getvalue())

    def test_02_container_file_interface_write_methods(self):
        data_orig_by_cntr_path = {}

        for cntr_path in self.fp_by_cntr_path:
            data_orig = _lorem()
            data_orig_by_cntr_path[cntr_path] = data_orig

            with Container.create(cntr_path, ssh_key_fp=self.fp_by_cntr_path[cntr_path], ) as cntr:
                cntr.write(b'b1')
                cntr.write('s2')
                cntr.writelines([b'b3', b'b3'])
                cntr.writelines(['b4', 'b4'])

        for cntr_path in self.fp_by_cntr_path:
            with Container.load(cntr_path) as cntr:
                self.assertEqual(cntr.getvalue(), b'b1s2b3b3b4b4')

    def test_03_container_file_interface_cleanup_empty(self):
        for cntr_path in self.fp_by_cntr_path:
            with Container.create(cntr_path) as cntr:
                self.assertIsInstance(cntr, Container)
            # Newly created containers shouldn't leave something behind, of not written to.
            self.assertFalse(os.path.exists(cntr_path))

    def test_04_container_file_interface_cleanup_empty(self):
        for cntr_path in self.fp_by_cntr_path:
            with Container.create(cntr_path) as cntr:
                self.assertIsInstance(cntr, Container)
            # Newly created containers shouldn't leave something behind, of not written to.
            self.assertFalse(os.path.exists(cntr_path))

    def test_05_container_file_interface_legacy_ciphers(self):
        data_orig_by_cntr_path = {}

        for cipher_name in [Cipher.AES_128_CBC, Cipher.DES_EDE3_CBC, Cipher.Blowfish_CBC]:

            for cntr_path in self.fp_by_cntr_path:
                data_orig = _lorem()
                cntr_path_variant = "{}.{}".format(cntr_path, cipher_name)
                data_orig_by_cntr_path[cntr_path_variant] = data_orig

                with Container.create(cntr_path_variant, ssh_key_fp=self.fp_by_cntr_path[cntr_path],
                                      data=data_orig, cipher_name=cipher_name) as cntr:
                    self.assertIsInstance(cntr, Container)

            for cntr_path in self.fp_by_cntr_path:
                cntr_path_variant = "{}.{}".format(cntr_path, cipher_name)
                cntr = Container.load(cntr_path_variant)
                self.assertEqual(data_orig_by_cntr_path[cntr_path_variant], cntr.getvalue())

    def test_06_container_stream_interface(self):
        for interpreter in ["python2", "python3"]:
            cntr_path = list(self.fp_by_cntr_path)[random.choice(range(0, len(self.fp_by_cntr_path)))]
            data_orig = _lorem()

            p_hndl = subprocess.Popen([interpreter, "-magentcrypt.io", "enc", self.fp_by_cntr_path[cntr_path]],
                                      stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
            data_encrypted = (p_hndl.communicate(data_orig))[0]

            p_hndl = subprocess.Popen([interpreter, "-magentcrypt.io", "dec", self.fp_by_cntr_path[cntr_path]],
                                      stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
            data_decrypted = (p_hndl.communicate(data_encrypted))[0].rstrip()

            self.assertEqual(data_decrypted, data_orig)

    def test_07_container_grow_data(self):
        cntr_path = list(self.fp_by_cntr_path)[random.choice(range(0, len(self.fp_by_cntr_path)))]
        data_orig_first = _lorem()
        cntr_path_variant = "{}.{}".format(cntr_path, "grow")

        cntr = Container.create(cntr_path_variant, ssh_key_fp=self.fp_by_cntr_path[cntr_path], data=data_orig_first)
        cntr.close()

        data_orig_second = _lorem()
        cntr = Container.load(cntr_path_variant)
        cntr.write(data_orig_second)
        cntr.close()

        data_orig_all = data_orig_first + data_orig_second
        with Container.load(cntr_path_variant) as cntr:
            self.assertEqual(data_orig_all, cntr.getvalue())

    def test_08_container_shrink_data(self):
        cntr_path = list(self.fp_by_cntr_path)[random.choice(range(0, len(self.fp_by_cntr_path)))]
        data_orig_first = _lorem(len=128)
        cntr_path_variant = "{}.{}".format(cntr_path, "shrink")

        cntr = Container.create(cntr_path_variant, ssh_key_fp=self.fp_by_cntr_path[cntr_path], data=data_orig_first)
        cntr.close()

        data_orig_second = _lorem(len=8)
        cntr = Container.load(cntr_path_variant)
        cntr.clear()
        cntr.write(data_orig_second)
        cntr.close()

        with Container.load(cntr_path_variant) as cntr:
            self.assertEqual(data_orig_second, cntr.getvalue())

    def test_09_container_rekey_data(self):
        cntr_path = list(self.fp_by_cntr_path)[random.choice(range(0, len(self.fp_by_cntr_path)))]
        data_orig = _lorem()
        cntr_path_variant = "{}.{}".format(cntr_path, "rekey")

        first_cipher = Cipher.DES_EDE3_CBC
        cntr = Container.create(cntr_path_variant, ssh_key_fp=self.fp_by_cntr_path[cntr_path],
                                cipher_name=first_cipher, data=data_orig)
        cntr.close()

        second_cipher = Cipher.AES_128_CBC
        with Container.load(cntr_path_variant) as cntr:
            cntr.rekey(second_cipher)

        # Load again
        with Container.load(cntr_path_variant) as cntr:
            self.assertEqual(data_orig, cntr.getvalue())
            self.assertEqual(second_cipher, cntr.cipher.cipher_name)


if __name__ == '__main__':
    unittest.main()
