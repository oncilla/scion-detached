"""
:mod:`sphinx_end_host` --- Sphinx End-Host
==========================================

This module defines the Sphinx end-host (source or destination), which can
create new Sphinx packets, reply headers and reply packets from reply headers.

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
from lib.privacy.sphinx.sphinx_node import SphinxNode
from lib.privacy.sphinx.packet import compute_blinded_header_size,\
    compute_pernode_size
from lib.privacy.sphinx.sphinx_crypto_util import stream_cipher_decrypt
import os


class SphinxEndHost(SphinxNode):
    """
    A Sphinx end host (source or destination), which can create new Sphinx
    packets, reply headers and reply packets from reply headers.

    :ivar public_key: public key of the SphinxNode
    :vartype public_key: bytes
    :ivar private_key: private key of the SphinxNode
    :vartype private_key: bytes
    :ivar max_hops: maximum number of nodes on the path
    :vartype max_hops: int
    :ivar address_length: length of a node address (name)
    :vartype address_length: int
    :ivar group_elem_length: length of a group element (for Diffie-Hellman)
    :vartype group_elem_length: int
    :ivar payload_length: length of the payload
    :vartype payload_length: int
    """
    #TODO/Daniele: check whether it is correct to specify the instance
    #    attributes "inherited" from the superclass

    def __init__(self, public_key, private_key):
        SphinxNode.__init__(self, public_key, private_key)

    def construct_header_from_keys(self, shared_keys, dh_pubkey_0, next_hops):
        """
        Constructs a new SphinxHeader

        :param shared_keys: List of keys shared with each node on the path
        :type shared_keys: list
        :param dh_pubkey_0: Diffie-Hellman public key (of the source)
            for the first node
        :type dh_pubkey_0: bytes
        :param next_hops: list of node names (addresses) on the path
        :type next_hops: list
        :returns: the newly-created SphinxHeader instance
        :rtype: :class:`SphinxHeader`
        """
        assert len(shared_keys) < self.max_hops
        for k in shared_keys:
            assert isinstance(k, bytes)
        assert len(next_hops) == len(shared_keys)
        for n in next_hops:
            assert isinstance(n, bytes)
            assert len(n) == self.address_length
        assert isinstance(dh_pubkey_0, bytes)
        assert len(dh_pubkey_0) == 32
        blinded_header_size = compute_blinded_header_size(self.max_hops,
                                                          self.address_length)
        pernode_size = compute_pernode_size(self.address_length)

        # Create filler string
        tmp_filler = b"0" * blinded_header_size
        for k in shared_keys:
            tmp_filler = stream_cipher_decrypt(k, tmp_filler)
        filler_length = pernode_size * (len(next_hops) - 1)
        filler = tmp_filler[-filler_length:]

        # Create the blinded header by reversing the decryption steps done
        # at each hop by the nodes, starting by the destination's decryption
        # of the blinded header it will receive.
        padding_length = (blinded_header_size - filler_length
                          - self.address_length)
        blinded_header = (self.get_localhost_address()
                          + os.urandom(padding_length) + filler)
        #TODO add for loop
        pass #TODO/daniele: implement this method

    def construct_forward_packet(self, message, shared_keys, header):
        """
        Constructs a new SphinxPacket to be sent by the source.
        It first constructs the header, then onion-encrypts the payload.

        :param message: the message to be sent as payload
        :type message: bytes or str
        :param shared_keys: List of keys shared with each node on the path
        :type shared_keys: list
        :param header: the reply SphinxHeader
        :type header: :class:`SphinxPacket`
        :returns: the newly-created SphinxPacket instance
        :rtype: :class:`SphinxPacket`
        """
        pass #TODO/daniele: implement this method

    def construct_reply_packet(self, message, shared_key, header):
        """
        Constructs a new replay SphinxPacket to be sent by the destination

        :param message: the message to be sent as payload
        :type message: bytes or str
        :param shared_key: the key shared between destination and source
        :type shared_key: bytes
        :param header: the reply SphinxHeader
        :type header: :class:`SphinxPacket`
        """
        pass #TODO/daniele: implement this method

