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
from lib.privacy.hornet_packet import get_packet_type, HornetPacketType,\
    TIMESTAMP_LENGTH, SHARED_KEY_LENGTH, ROUTING_INFO_LENGTH, FS_LENGTH
from lib.privacy.hornet_crypto_util import fs_shared_key_encrypt,\
    derive_fs_encdec_key, fs_shared_key_decrypt, generate_fs_encdec_iv
from curve25519.keys import Private
import time
from lib.privacy.sphinx.sphinx_crypto_util import stream_cipher_encrypt,\
    stream_cipher_decrypt


class HornetNode(object):
    """
    A Hornet node, able to process packets of the setup phase
    (:class:`hornet_packet.SetupPacket`) and of the data forwarding phase
    (:class:`hornet_packet.DataPacket`).

    :ivar secret_key: secret key of the HornetNode (SV in the paper)
    :vartype secret_key: bytes
    :ivar private: private key of the HornetNode
    :vartype private: bytes or :class:`curve25519.keys.Private`
    :ivar public: public key of the HornetNode
    :vartype public: bytes
    """

    def __init__(self, secret_key, private=None, public=None, sphinx_node=None):
        assert isinstance(secret_key, bytes)
        if sphinx_node is not None:
            assert isinstance(sphinx_node, SphinxNode)
            assert private is None, "provide private or sphinx_node, not both"
            self._sphinx_node = sphinx_node
        else:
            assert private is not None, ("parameter private and sphinx_node"
                                         "cannot both be None")
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

    def create_forwarding_segment(self, shared_key, routing_info,
                                  expiration_time):
        """
        Create a forwarding segment (to be added to the FS payload)
        """
        assert isinstance(shared_key, bytes)
        assert len(shared_key) == SHARED_KEY_LENGTH
        assert isinstance(routing_info, bytes)
        assert len(routing_info) == ROUTING_INFO_LENGTH
        if not isinstance(expiration_time, bytes):
            assert isinstance(expiration_time, int)
            expiration_time = expiration_time.to_bytes(TIMESTAMP_LENGTH, "big")
        else:
            assert len(expiration_time) == TIMESTAMP_LENGTH
        forwarding_segment = fs_shared_key_encrypt(self.secret_key, shared_key)
        fs_stream_key = derive_fs_encdec_key(shared_key)
        fs_iv = generate_fs_encdec_iv(shared_key)
        forwarding_segment += stream_cipher_encrypt(fs_stream_key,
                                                    routing_info +
                                                    expiration_time, fs_iv)
        return forwarding_segment

    def decrypt_forwarding_segment(self, forwarding_segment):
        """
        Decrypt a forwarding segment and return the data it contained, which
        will be a tuple of the form (shared_key, routing_info, expiration_time)
        """
        assert isinstance(forwarding_segment, bytes)
        assert len(forwarding_segment) == FS_LENGTH
        encrypted_fs_shared_key = forwarding_segment[:SHARED_KEY_LENGTH]
        shared_key = fs_shared_key_decrypt(self.secret_key,
                                           encrypted_fs_shared_key)
        fs_stream_key = derive_fs_encdec_key(shared_key)
        fs_iv = generate_fs_encdec_iv(shared_key)
        raw = stream_cipher_decrypt(fs_stream_key,
                                    forwarding_segment[SHARED_KEY_LENGTH:],
                                    fs_iv)
        routing_info = raw[:ROUTING_INFO_LENGTH]
        expiration_time = raw[ROUTING_INFO_LENGTH:]
        return (shared_key, routing_info, expiration_time)

    def process_incoming_packet(self, raw_packet):
        """
        Process an incoming Hornet packet (:class:`hornet_packet.SetupPacket`
        or :class:`hornet_packet.DataPacket`)
        """
        packet_type = get_packet_type(raw_packet) # Fails if type unknown
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


def test():
    private = Private()
    secret_key = b'1'*32
    node = HornetNode(secret_key, private)

    shared_key = b'2'*16
    routing_info = b'3'*ROUTING_INFO_LENGTH
    expiration_time = int(time.time()).to_bytes(TIMESTAMP_LENGTH, "big")
    forwarding_segment = node.create_forwarding_segment(shared_key,
                                                        routing_info,
                                                        expiration_time)
    dec_tuple = node.decrypt_forwarding_segment(forwarding_segment)
    assert dec_tuple == (shared_key, routing_info, expiration_time)


if __name__ == "__main__":
    test()
