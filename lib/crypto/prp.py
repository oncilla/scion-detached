"""
:mod:`prp` --- Pseudo-Random Permutation function
=================================================

IMPORTANT: The security of this module has not been formally proven by the
author, and is just a proof-of-concept implementation. Do NOT use the
functions of this module in production code.

This module defines a keyed Pseudo-Random Permutation (PRP), also known as
Block Cipher, of arbitrarily large block size.
Such a PRP allows encryption and decryption with the guarantee that any change
in the plaintext will propagate to all the bits of the ciphertext, and vice
versa any change in the ciphertext will propagate to all the bits of the
recovered plaintext.

It is implemented using two passes of encryption with the Propagating-CBC mode
for AES (implemented manually since not available in pycrytpo library).
The mode was tweaked by adding hashing for the history at every block, avoiding
the attack of ciphertext blocks swapping (because of the linearity of vanilla
P-CBC this change does not propagate to the rest of the plaintext).

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
from hashlib import sha1
from hashlib import sha256
from Crypto.Util import Counter
# pylint: disable=no-name-in-module
try:
    from Crypto.Util.strxor import strxor
except ImportError:
    from Crypto.Hash.HMAC import _strxor as strxor
# pylint: enable=no-name-in-module

BLOCK_SIZE = AES.block_size
ZEROED_IV = b'\x00' * BLOCK_SIZE


def _xor(bytes_1, bytes_2):
    """
    Xor together two or three byte sequences bitwise.
    """
    assert len(bytes_1) == len(bytes_2)
    return strxor(bytes_1, bytes_2)


def encrypt_with_aes_pcbc(key, msg, iv=ZEROED_IV):
    """
    Encrypt the given message with AES in Propagating-CBC mode.
    """
    assert isinstance(key, bytes)
    assert isinstance(msg, bytes)
    assert len(msg) % BLOCK_SIZE == 0
    aes = AES.new(key, mode=AES.MODE_ECB)

    ciphertext = aes.encrypt(_xor(msg[:BLOCK_SIZE], iv))
    for i in range(1,len(msg) // BLOCK_SIZE):
        hashed_past = sha1(msg[BLOCK_SIZE * (i-1):BLOCK_SIZE * i]
                           + ciphertext[-BLOCK_SIZE:]).digest()[:16]
        ciphertext += aes.encrypt(_xor(msg[BLOCK_SIZE * i:BLOCK_SIZE * (i+1)],
                                  hashed_past))
    return ciphertext


def decrypt_with_aes_pcbc(key, ciphertext, iv=ZEROED_IV):
    """
    Decrypt the given ciphertext with AES in Propagating-CBC mode.
    """
    assert isinstance(key, bytes)
    assert isinstance(ciphertext, bytes)
    assert len(ciphertext) % BLOCK_SIZE == 0
    aes = AES.new(key, mode=AES.MODE_ECB)

    msg = _xor(aes.decrypt(ciphertext[:BLOCK_SIZE]), iv)
    for i in range(1,len(ciphertext) // BLOCK_SIZE):
        hashed_past = sha1(msg[-BLOCK_SIZE:]
                           + ciphertext[BLOCK_SIZE * (i-1):
                                        BLOCK_SIZE * i]).digest()[:16]
        msg += _xor(aes.decrypt(ciphertext[BLOCK_SIZE * i:BLOCK_SIZE * (i+1)]),
                    hashed_past)
    return msg

# pylint: disable=invalid-name

def lioness_enc(key, message):
    k = len(key)
    assert len(message) >= k * 2
    # Round 1
    r1 = _xor(sha256(message[k:]+key+b'1').digest()[:k],
            message[:k]) + message[k:]

    # Round 2
    k2 = _xor(r1[:k], key)
    c = AES.new(k2, AES.MODE_CTR, counter=Counter.new(128))
    r2 = r1[:k] + c.encrypt(r1[k:])

    # Round 3
    r3 = _xor(sha256(r2[k:]+key+b'3').digest()[:k], r2[:k]) + r2[k:]

    # Round 4
    k4 = _xor(r3[:k], key)
    c = AES.new(k4, AES.MODE_CTR, counter=Counter.new(128))
    r4 = r3[:k] + c.encrypt(r3[k:])

    return r4

def lioness_dec(key, message):
    k = len(key)
    assert len(message) >= k * 2

    r4 = message

    # Round 4
    k4 = _xor(r4[:k], key)
    c = AES.new(k4, AES.MODE_CTR, counter=Counter.new(128))
    r3 = r4[:k] + c.encrypt(r4[k:])

    # Round 3
    r2 = _xor(sha256(r3[k:]+key+b'3').digest()[:k], r3[:k]) + r3[k:]

    # Round 2
    k2 = _xor(r2[:k], key)
    c = AES.new(k2, AES.MODE_CTR, counter=Counter.new(128))
    r1 = r2[:k] + c.encrypt(r2[k:])

    # Round 1
    r0 = _xor(sha256(r1[k:]+key+b'1').digest()[:k], r1[:k]) + r1[k:]

    return r0

# pylint: enable=invalid-name


def prp_encrypt(prp_key, msg):
    """
    Encrypt msg using a PRP keyed with the input key. The reverse operation is
    :func:`prp_encrypt`, but since it is a PRP it has the property that
    :func:`prp_decrypt`(:func:`prp_encrypt`(msg)) =
    :func:`prp_encrypt`(:func:`prp_decrypt`(msg)) = msg.
    """
    assert isinstance(prp_key, bytes)
    assert isinstance(msg, bytes)
    assert len(msg) % BLOCK_SIZE == 0
#     intermediate_ciphertext = bytes(
#         reversed(encrypt_with_aes_pcbc(prp_key, msg)))
#     return encrypt_with_aes_pcbc(prp_key, intermediate_ciphertext)
    return lioness_enc(prp_key, msg)


def prp_decrypt(prp_key, ciphertext):
    """
    Decrypt the ciphertext using a PRP keyed with the input key. It reverses
    :func:`prp_encrypt`, but since it is a PRP it has the property that
    :func:`prp_decrypt`(:func:`prp_encrypt`(msg)) =
    :func:`prp_encrypt`(:func:`prp_decrypt`(msg)) = msg.
    """
    assert isinstance(prp_key, bytes)
    assert isinstance(ciphertext, bytes)
    assert len(ciphertext) % BLOCK_SIZE == 0
#     intermediate_ciphertext = bytes(
#         reversed(decrypt_with_aes_pcbc(prp_key, ciphertext)))
#     return decrypt_with_aes_pcbc(prp_key, intermediate_ciphertext)
    return lioness_dec(prp_key, ciphertext)


def test():
    key = b'4' * 32
    msg = b'1234123412341234' * 40
    ciphertext = prp_encrypt(key, msg)
    plaintext = prp_decrypt(key, ciphertext)
    assert plaintext == msg
    # Try reversed, first decrypting and then encrypting
    rev_ciphertext = prp_decrypt(key, msg)
    plaintext = prp_encrypt(key, rev_ciphertext)
    assert plaintext == msg

if __name__ == "__main__":
    test()

