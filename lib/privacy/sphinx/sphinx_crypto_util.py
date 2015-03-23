"""
:mod:`sphinx_crypto_util` --- Cryptographic Utilities
=====================================================

This module defines a number of cryptographic utility functions
needed by the Sphinx protocol.
The functions defined here are just wrappers of library functions.

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
#TODO/dasoni: add Sphinx reference
from curve25519.keys import Private, Public
from Crypto.Cipher import AES
from Crypto.Util import Counter
from hashlib import sha256
import hmac
from lib.privacy.common.constants import MAC_SIZE


BLOCK_SIZE = AES.block_size
_PAD_START_BYTE = b'\xFF'
_PAD_BYTE = b'\x00'


class PaddingFormatError(ValueError):
    """
    Error indicating that it was not possible to remove a padding from
    a message because the provided message is not in the right format.
    """
    pass


def pad_to_block_multiple(msg, block_size=BLOCK_SIZE):
    """
    Pad the input message to a multiple of the block size (as done in PKCS#7)
    """
    assert isinstance(msg, bytes)
    pad_length = block_size - (len(msg) % block_size)
    return msg + pad_length * bytes([pad_length])


def remove_block_pad(padded_msg):
    """
    Remove padding to block size multiple from the input message (as done in
    PKCS#7).
    """
    assert isinstance(padded_msg, bytes)
    if padded_msg[-1:] == b'\0':
        raise PaddingFormatError("message is not padded as expected")
    pad_length = int.from_bytes(padded_msg[-1:], byteorder='little')
    if pad_length > len(padded_msg):
        raise PaddingFormatError("message is not padded as expected")
    return padded_msg[:-pad_length]


def pad_to_length(msg, final_length):
    """
    Pad the input message to the desired length. Since the padding requires
    at least one byte to be appended to the message, the final_length needs to
    be larger than the length of the message.
    """
    assert len(msg) < final_length # One byte at least needed for the padding
    return msg + _PAD_START_BYTE + _PAD_BYTE * (final_length - len(msg) - 1)


def remove_length_pad(msg):
    """
    Remove length padding added with :func:`pad_to_length`.
    """
    msg_without_pad_bytes = msg.rstrip(_PAD_BYTE)
    if msg_without_pad_bytes[-1:] != _PAD_START_BYTE:
        raise PaddingFormatError("message is not padded as expected")
    return msg_without_pad_bytes[:-1]


def derive_mac_key(shared_key):
    """
    Derive the key for the MAC (Message Authentication Code) from the
    established shared key.
    """
    assert isinstance(shared_key, bytes)
    return sha256(b"sphinx-keyderivation-mac:"+shared_key).digest()


def derive_stream_key(shared_key):
    """
    Derive the key for the stream cipher from the established shared key.
    """
    assert isinstance(shared_key, bytes)
    return sha256(b"sphinx-keyderivation-stream:"+shared_key).digest()


def derive_prp_key(shared_key):
    """
    Derive the key for the PRP (Pseudo-Random Permutation) from the
    established shared key.
    """
    assert isinstance(shared_key, bytes)
    return sha256(b"sphinx-keyderivation-prp:"+shared_key).digest()


def compute_mac(mac_key, msg):
    """
    Computes a MAC (Message Authentication Code) over a message.

    :param mac_key: the secret key for the MAC computation
    :type mac_key: bytes
    :param msg: the message over which the MAC is computed
    :type msg: bytes or str
    :returns: a MAC
    :rtype: bytes
    """
    assert isinstance(mac_key, bytes)
    digester = hmac.new(mac_key, msg, sha256)
    return digester.digest()[:MAC_SIZE]


def verify_mac(mac_key, msg, mac):
    """
    Verifies that the MAC (Message Authentication Code) corresponds
    to the input message.

    :param mac_key: the secret key for the MAC computation
    :type mac_key: bytes
    :param msg: the message over which the MAC is computed, i.e. the integrity
        of which needs to be verified
    :type msg: bytes or str
    :param mac: the MAC for the verification of the message
    :type mac: bytes
    :returns: Returns True if the verification succeeded, false otherwise
    :rtype: bool
    """
    assert isinstance(mac_key, bytes)
    assert isinstance(mac, bytes)
    assert len(mac) == MAC_SIZE
    digester = hmac.new(mac_key, msg, sha256)
    recomputed_mac = digester.digest()[:MAC_SIZE]
    return hmac.compare_digest(mac, recomputed_mac)


def stream_cipher_encrypt(stream_key, plaintext, initial_value=1):
    """
    Encrypt the given plaintext (byte sequence) using a stream cipher.

    :param stream_key: the secret key for the encryption
    :type stream_key: bytes
    :param plaintext: the plaintext to encrypt (byte sequence)
    :type plaintext: bytes
    :returns: the encrypted plaintext, as byte sequence with the same length
        as the plaintext.
    :rtype: bytes
    """
    assert isinstance(stream_key, bytes)
    assert isinstance(plaintext, bytes)
    if not isinstance(initial_value, int):
        assert isinstance(initial_value, bytes)
        initial_value = int.from_bytes(initial_value, "big")
    ctr = Counter.new(128, initial_value=initial_value)
    aes_instance = AES.new(stream_key, mode=AES.MODE_CTR, counter=ctr)
    return aes_instance.encrypt(plaintext)


def stream_cipher_decrypt(stream_key, ciphertext, initial_value=1):
    """
    Decrypt the given ciphertext (byte sequence) using a stream cipher.

    :param stream_key: the secret key for the decryption
    :type stream_key: bytes
    :param ciphertext: the ciphertext to decrypt (byte sequence)
    :type ciphertext: bytes
    :returns: the decrypted ciphertext, a byte sequence with the same length
        as the ciphertext.
    :rtype: bytes
    """
    assert isinstance(stream_key, bytes)
    assert isinstance(ciphertext, bytes)
    if not isinstance(initial_value, int):
        assert isinstance(initial_value, bytes)
        initial_value = int.from_bytes(initial_value, "big")
    ctr = Counter.new(128, initial_value=initial_value)
    aes_instance = AES.new(stream_key, mode=AES.MODE_CTR, counter=ctr)
    return aes_instance.decrypt(ciphertext)


def compute_blinding_private(dh_pubkey, shared_key):
    """
    Compute the secret needed for the blinding (see :func:`blind_dh_key`).
    This is not the blinding factor as in the Sphinx paper, which instead will
    be computed by the :func:`blind_dh_key` function.
    """
    if isinstance(dh_pubkey, Public):
        dh_pubkey = dh_pubkey.serialize()
    else:
        assert isinstance(dh_pubkey, bytes)
        assert len(dh_pubkey) == 32
    assert isinstance(shared_key, bytes)
    secret_for_blinding = sha256(b"sphinx-blinding-factor:" + dh_pubkey +
                                 shared_key).digest()
    return Private(secret=secret_for_blinding)


def test():
    m1 = b'1234'
    m2 = b'1234\0\0\0\0'
    assert remove_block_pad(pad_to_block_multiple(m1, 32)) == m1
    assert remove_length_pad(pad_to_length(m1, 200)) == m1
    assert remove_block_pad(pad_to_block_multiple(m2, 8)) == m2
    assert remove_length_pad(pad_to_length(m2, 9)) == m2
    assert remove_length_pad(remove_block_pad(
        pad_to_block_multiple(pad_to_length(m1, 100), 32))) == m1

    shared_key = b'5' * 32
    mac_key = derive_mac_key(shared_key)
    stream_key = derive_stream_key(shared_key)
    prp_key = derive_stream_key(shared_key)
    assert len(mac_key) == 32
    assert len(stream_key) == 32
    assert len(prp_key) == 32

    msg = b'hellotoall' * 10
    assert verify_mac(mac_key, msg, compute_mac(mac_key, msg))
    ciphertext = stream_cipher_encrypt(stream_key, msg)
    assert stream_cipher_decrypt(stream_key, ciphertext) == msg
    rev_ciphertext = stream_cipher_decrypt(stream_key, msg)
    assert stream_cipher_encrypt(stream_key, rev_ciphertext) == msg
    assert ciphertext == rev_ciphertext

    mod_ciphertext = ciphertext[0:10] + b'0' + ciphertext[11:]
    mod_msg = stream_cipher_decrypt(stream_key, mod_ciphertext)
    assert mod_msg[0:10] == msg[0:10]
    assert mod_msg[11:] == msg[11:]


if __name__ == "__main__":
    test()
