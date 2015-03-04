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

    def construct_header(self, shared_keys, next_hops, dh_pubkey_0=None):
        """
        Constructs a new SphinxHeader

        :param shared_keys: List of keys shared with each node on the path
        :type shared_keys: list
        :param next_hops: list of node names (addresses) on the path
        :type next_hops: list
        :param dh_pubkey_0: Diffie-Hellman public key (of the source)
            for the first node
        :type dh_pubkey_0: bytes
        :param max_hops: maximum number of nodes on the path
        :type max_hops: int
        :returns: the newly-created SphinxHeader instance
        :rtype: :class:`SphinxHeader`
        """
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

