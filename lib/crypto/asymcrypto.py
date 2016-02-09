# Copyright 2014 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`asymcrypto` --- SCION asymmetric crypto functions
=======================================================
"""
# External
from nacl.exceptions import BadSignatureError
from nacl.encoding import Base64Encoder
from nacl.utils import random as rand_nonce
from nacl.public import Box, PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey


def generate_sign_keypair():
    """
    Generate Ed25519 keypair.

    :returns: a pair containing the signing key and the verifying key.
    :rtype: bytes
    """
    sk = SigningKey.generate()
    return sk.verify_key.encode(), sk.encode()


def sign(msg, signing_key):
    """
    Sign a message with a given signing key and return the signature.

    :param msg: message to be signed.
    :type msg: bytes
    :param signing_key: signing key from generate_signature_keypair().
    :type signing_key: bytes

    :returns: ed25519 signature.
    :rtype: bytes
    """
    return SigningKey(signing_key).sign(msg)[:64]


def verify(msg, sig, verifying_key):
    """
    Verify a signature.

    :param msg: message that was signed.
    :type msg: bytes
    :param sig: signature to verify.
    :type sig: bytes
    :param verifying_key: verifying key from generate_signature_keypair().
    :type verifying_key: bytes

    :returns: True or False whether the verification succeeds or fails.
    :rtype: boolean
    """
    try:
        return msg == VerifyKey(verifying_key).verify(msg, sig)
    except BadSignatureError:
        return False


def encrypt_session_key(private_key, public_key, msg):
    """

    :param private_key:
    :type private_key: bytes
    :param public_key:
    :type public_key: bytes
    :param msg:
    :type msg: bytes
    :return:
    """

    sk = PrivateKey(private_key)
    pk = PublicKey(public_key)
    box = Box(sk, pk)
    nonce = rand_nonce(Box.NONCE_SIZE)
    encrypted = box.encrypt(msg, nonce)
    return encrypted


def decrypt_session_key(private_key, public_key, cypher):
    """

    :param private_key:
    :type private_key: bytes
    :param public_key:
    :type public_key: bytes
    :param cypher:
    :type cypher: bytes
    :return:
    """
    sk = PrivateKey(private_key)
    pk = PublicKey(public_key)
    box = Box(sk, pk)
    encrypted = box.decrypt(cypher)
    return encrypted
