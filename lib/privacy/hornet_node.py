"""
:mod:`hornet_node` --- HORNET node
==================================

This module defines the HORNET node, main processing unit
of the HORNET protocol.

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
from lib.privacy.sphinx.sphinx_node import SphinxNode
from lib.privacy.hornet_packet import get_packet_type, HornetPacketType


class HornetNode(object):
    """
    A Hornet node, able to process packet of the setup phase
    (:class:`hornet_packet.SetupPacket`) and of the data forwarding phase
    (:class:`hornet_packet.DataPacket`).

    :ivar secret_key: secret key of the HornetNode (SV in the paper)
    :vartype secret_key: bytes
    :ivar private: private key of the HornetNode
    :vartype private: bytes or :class:`curve25519.keys.Private`
    :ivar public: public key of the HornetNode
    :vartype public: bytes
    """

    def __init__(self, secret_key, private, public=None):
        assert isinstance(secret_key, bytes)
        self._sphinx_node = SphinxNode(private, public)
        self.secret_key = secret_key

    @property
    def private(self):
        """
        Getter for private property
        """
        return self._sphinx_node.private

    @private.setter
    def private(self, new_private):
        """
        Setter for private property
        """
        self._sphinx_node.private = new_private

    @property
    def public(self):
        """
        Getter for public property
        """
        return self._sphinx_node.public

    @public.setter
    def public(self):
        """
        Setter for public property (setting not allowed).
        """
        raise TypeError("Cannot assign directly to public property, "
                        "assign to private property instead")

    def create_forwarding_segment(self, routing_info, expiration_time):
        """
        Create a forwarding segment (to be added to the FS payload)
        """
        #TODO:Daniele: implement

    def process_incoming_packet(self, raw_packet):
        """
        Process an incoming Hornet packet (:class:`hornet_packet.SetupPacket`
        or :class:`hornet_packet.DataPacket`)
        """
        packet_type = get_packet_type(raw_packet)
        if packet_type in HornetPacketType.SETUP_TYPES:
            return self.process_setup_packet(raw_packet)
        else:
            return self.process_data_packet(raw_packet)

    def process_setup_packet(self, raw_packet):
        """
        Process an incoming Hornet setup packet
        (:class:`hornet_packet.SetupPacket`)
        """
        #TODO:Daniele: implement

    def process_data_packet(self, raw_packet):
        """
        Process an incoming Hornet data packet
        (:class:`hornet_packet.DataPacket`)
        """
        #TODO:Daniele: implement

