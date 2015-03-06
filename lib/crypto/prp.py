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
from hashlib import sha256


BLOCK_SIZE = AES.block_size
ZEROED_IV = b'\x00' * BLOCK_SIZE


def _xor(bytes_1, bytes_2, bytes_3=None):
    """
    Xor together two or three byte sequences bitwise.
    """
    assert len(bytes_1) == len(bytes_2)
    if bytes_3 is not None:
        return bytes([b1 ^ b2 ^ b3
                      for b1, b2, b3 in zip(bytes_1, bytes_2, bytes_3)])
    else:
        return bytes([b1 ^ b2 for b1, b2 in zip(bytes_1, bytes_2)])


def _pad(msg, block_size=BLOCK_SIZE):
    """
    Pad the input message to a multiple of the block size (as done in PKCS#7)
    """
    assert isinstance(msg, bytes)
    assert block_size < 256
    pad_length = block_size - (len(msg) % block_size)
    return msg + pad_length * bytes([pad_length])

def _unpad(padded_msg):
    """
    Remove padding from the input message (as done in PKCS#7)
    """
    assert isinstance(padded_msg, bytes)
    pad_length = int.from_bytes(padded_msg[-1:], byteorder='little')
    return padded_msg[:-pad_length]


def encrypt_with_aes_pcbc(key, msg, iv=ZEROED_IV):
    """
    Encrypt the given message with AES in Propagating-CBC mode.
    """
    assert isinstance(key, bytes)
    assert isinstance(msg, bytes)
    assert len(msg) % BLOCK_SIZE == 0
    aes = AES.new(key, mode=AES.MODE_ECB)

    nth_block = lambda m, i: m[BLOCK_SIZE * i:BLOCK_SIZE * (i+1)]
    last_block = lambda c: c[-BLOCK_SIZE:]

    ciphertext = aes.encrypt(_xor(nth_block(msg, 0), iv))
    for i in range(1,len(msg) // BLOCK_SIZE):
        ciphertext += aes.encrypt(_xor(nth_block(msg, i), nth_block(msg, i-1),
                                       last_block(ciphertext)))
    return ciphertext


def decrypt_with_aes_pcbc(key, ciphertext, iv=ZEROED_IV):
    """
    Decrypt the given ciphertext with AES in Propagating-CBC mode.
    """
    assert isinstance(key, bytes)
    assert isinstance(ciphertext, bytes)
    assert len(ciphertext) % BLOCK_SIZE == 0
    aes = AES.new(key, mode=AES.MODE_ECB)

    nth_block = lambda m, i: m[BLOCK_SIZE * i:BLOCK_SIZE * (i+1)]
    last_block = lambda c: c[-BLOCK_SIZE:]

    msg = _xor(aes.decrypt(nth_block(ciphertext, 0)), iv)
    for i in range(1,len(ciphertext) // BLOCK_SIZE):
        msg += _xor(aes.decrypt(nth_block(ciphertext, i)),
                    nth_block(ciphertext, i-1), last_block(msg))
    return msg


def prp_encrypt(prp_key, msg):
    """
    """
    assert isinstance(prp_key, bytes)
    assert isinstance(msg, bytes)
    msg = _pad(msg)
    intermediate_ciphertext = bytes(
        reversed(encrypt_with_aes_pcbc(prp_key, msg)))
    return encrypt_with_aes_pcbc(prp_key, intermediate_ciphertext)


def prp_decrypt(prp_key, ciphertext):
    """
    """
    assert isinstance(prp_key, bytes)
    assert isinstance(ciphertext, bytes)
    intermediate_ciphertext = bytes(
        reversed(decrypt_with_aes_pcbc(prp_key, ciphertext)))
    padded_msg = decrypt_with_aes_pcbc(prp_key, intermediate_ciphertext)
    return _unpad(padded_msg)


def main():
    key = b'4' * 32
    msg = b'ciaociaociaociaoL' * 3
    ciphertxt = prp_encrypt(key, msg)
    plaintext = prp_decrypt(key, ciphertxt)
    assert plaintext == msg

if __name__ == "__main__":
    main()

