"""
:mod:`packet` --- Sphinx packet format
======================================

This module defines the Sphinx packet format.

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
from hashlib import sha256
from curve25519.keys import Private, Public


def derive_mac_key(shared_key):
    """
    Derive the key for the MAC (Message Authentication Code) from the
    established shared key.
    """
    assert isinstance(shared_key, bytes)
    return sha256(b"sphinx-keyderivation-mac:"+shared_key).digest()

def derive_prg_key(shared_key):
    """
    Derive the key for the PRG (Pseudo-Random Generator) from the
    established shared key.
    """
    assert isinstance(shared_key, bytes)
    return sha256(b"sphinx-keyderivation-prg:"+shared_key).digest()

def derive_prp_key(shared_key):
    """
    Derive the key for the PRP (Pseudo-Random Permutation) from the
    established shared key.
    """
    assert isinstance(shared_key, bytes)
    return sha256(b"sphinx-keyderivation-prp:"+shared_key).digest()

def blind_dh_key(dh_pubkey, shared_key):
    """
    Derive the DH public key half (of the source) for the next hop
    based on the current public key and the established shared key.
    """
    assert isinstance(dh_pubkey, bytes)
    assert len(dh_pubkey) == 32
    assert isinstance(shared_key, bytes)
    # The following is a hack to reuse the python wrapper
    # of the curve25519-donna library to generate an element in Z_q^*.
    # First a secret is created hashing dh_pubkey and share_key, but unlike
    # in the Sphinx paper, this hash will not be an element of Z_q^*, just a
    # random byte sequence. This is used to generate a "fake" DH private key,
    # which represents the actual blinding factor. Blinding the dh_pubkey is
    # equivalent to computing a shared secret (which is another group element).
    secret_for_blind_factor = sha256(b"sphinx-blinding-factor:"
                                     + dh_pubkey + shared_key).digest()
    blinding_factor = Private(secret=secret_for_blind_factor)
    blinded_dh_pubkey = blinding_factor.get_shared_public(Public(dh_pubkey))
    return blinded_dh_pubkey.serialize()

