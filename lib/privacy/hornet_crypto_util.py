"""
:mod:`hornet_crypto_util` --- Cryptographic Utilities
=====================================================

This module defines a number of cryptographic utility functions
needed by the Hornet protocol.
The functions defined here are mainly wrappers of library functions.

Copyright 2014 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from Crypto.Cipher import AES
from Crypto.Util import Counter
from hashlib import sha256
from lib.privacy.hornet_packet import SHARED_KEY_LENGTH


ZEROED_IV = b'\0'*AES.block_size


def generate_initial_fs_payload(shared_sphinx_key, fs_payload_length):
    """
    Works as PRG keyed with the input shared_sphinx_key, outputting a
    pseudo-random string of length fs_payload_length, to be used for the
    generation of the initial FS payload.
    """
    assert isinstance(shared_sphinx_key, bytes)
    assert isinstance(fs_payload_length, int)
    prg_key = sha256(b"hornet-keyderivation-fs-payload-prg:" +
                     shared_sphinx_key).digest()
    ctr = Counter.new(128)
    aes_instance = AES.new(prg_key, mode=AES.MODE_CTR, counter=ctr)
    return aes_instance.encrypt(b'\0'*fs_payload_length)


def _derive_fs_key_encdec_key(node_secret_key):
    """
    Derive the key for the encryption/decryption of the shared key in the
    forwarding segment from the secret key (SV) of the node.
    """
    assert isinstance(node_secret_key, bytes)
    return sha256(b"hornet-keyderivation-fs-key-encdec:" +
                  node_secret_key).digest()


def fs_shared_key_encrypt(node_secret_key, fs_shared_key):
    """
    Encrypt the shared key (as first part of a forwarding segment) with the
    node's secret key.
    """
    assert isinstance(node_secret_key, bytes)
    assert isinstance(fs_shared_key, bytes)
    assert len(fs_shared_key) == SHARED_KEY_LENGTH
    aes_instance = AES.new(_derive_fs_key_encdec_key(node_secret_key),
                           mode=AES.MODE_CBC, IV=ZEROED_IV)
    return aes_instance.encrypt(fs_shared_key)


def fs_shared_key_decrypt(node_secret_key, encrypted_fs_shared_key):
    """
    Decrypt the shared key (first part of a forwarding segment) with the node's
    secret key.
    """
    assert isinstance(node_secret_key, bytes)
    assert isinstance(encrypted_fs_shared_key, bytes)
    assert len(encrypted_fs_shared_key) == SHARED_KEY_LENGTH
    aes_instance = AES.new(_derive_fs_key_encdec_key(node_secret_key),
                           mode=AES.MODE_CBC, IV=ZEROED_IV)
    return aes_instance.decrypt(encrypted_fs_shared_key)


def test():
    shared_sphinx_key = b'1'*16
    fs_payload_length = 800
    fs_payload_1 = generate_initial_fs_payload(shared_sphinx_key,
                                               fs_payload_length)
    fs_payload_2 = generate_initial_fs_payload(shared_sphinx_key,
                                               fs_payload_length)
    assert len(fs_payload_1) == fs_payload_length
    assert fs_payload_1 == fs_payload_2
    assert isinstance(fs_payload_1, bytes)

    node_secret_key = b'2'*32
    fs_shared_key = b'3'*16
    enc_fs_key = fs_shared_key_encrypt(node_secret_key, fs_shared_key)
    dec_fs_key = fs_shared_key_decrypt(node_secret_key, enc_fs_key)
    assert dec_fs_key == fs_shared_key


if __name__ == "__main__":
    test()