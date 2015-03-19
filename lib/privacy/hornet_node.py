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
    TIMESTAMP_LENGTH, SHARED_KEY_LENGTH, ROUTING_INFO_LENGTH, FS_LENGTH,\
    SetupPacket, MAC_SIZE
from lib.privacy.hornet_crypto_util import fs_shared_key_encrypt,\
    fs_shared_key_decrypt, generate_fs_encdec_iv, derive_fs_payload_stream_key,\
    derive_fs_payload_mac_key
from curve25519.keys import Private, Public
import time
from lib.privacy.sphinx.sphinx_crypto_util import stream_cipher_encrypt,\
    stream_cipher_decrypt, compute_mac
from lib.privacy.common.exception import PacketParsingException
from lib.privacy.hornet_processing import HornetProcessingResult


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
        fs_iv = generate_fs_encdec_iv(shared_key)
        forwarding_segment += stream_cipher_encrypt(self.secret_key,
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
        fs_iv = generate_fs_encdec_iv(shared_key)
        raw = stream_cipher_decrypt(self.secret_key,
                                    forwarding_segment[SHARED_KEY_LENGTH:],
                                    fs_iv)
        routing_info = raw[:ROUTING_INFO_LENGTH]
        expiration_time = raw[ROUTING_INFO_LENGTH:]
        return (shared_key, routing_info, expiration_time)

    @staticmethod
    def add_fs_to_fs_payload(sphinx_shared_key, forwarding_segment,
                             tmp_pubkey, fs_payload):
        """
        Add a forwarding segment to an FS payload
        """
        fs_and_pubkey = forwarding_segment + tmp_pubkey
        added_size = len(fs_and_pubkey) + MAC_SIZE
        # Add FS and tmp_pubkey to fs_payload and encrypt it
        tmp_payload = fs_and_pubkey + fs_payload[:-added_size]
        stream_key = derive_fs_payload_stream_key(sphinx_shared_key)
        tmp_payload = stream_cipher_encrypt(stream_key, tmp_payload)
        # Compute MAC over new FS payload and prepend it to the payload
        mac_key = derive_fs_payload_mac_key(sphinx_shared_key)
        mac = compute_mac(mac_key, tmp_payload)
        return mac + tmp_payload

    def process_incoming_packet(self, raw_packet):
        """
        Process an incoming Hornet packet (:class:`hornet_packet.SetupPacket`
        or :class:`hornet_packet.DataPacket`), and return an instance of class
        :class:`hornet_processing.HornetProcessingResult`.
        """
        assert isinstance(raw_packet, bytes)
        packet_type = get_packet_type(raw_packet) # Fails if type unknown
        if packet_type in HornetPacketType.SETUP_TYPES:
            return self.process_setup_packet(raw_packet)
        else:
            return self.process_data_packet(raw_packet)

    def process_setup_packet(self, raw_packet):
        """
        Process an incoming Hornet setup packet
        (:class:`hornet_packet.SetupPacket`), and return an instance of class
        :class:`hornet_processing.HornetProcessingResult`.
        """
        try:
            packet = SetupPacket.parse_bytes_to_packet(raw_packet)
        except PacketParsingException:
            return HornetProcessingResult(HornetProcessingResult.Type.INVALID)
        if packet.expiration_time <= int(time.time()):
            return HornetProcessingResult(HornetProcessingResult.Type.INVALID)
        # Process the sphinx packet
        sphinx_packet = packet.sphinx_packet
        try:
            sphinx_processing_result = \
                self._sphinx_node.get_packet_processing_result(sphinx_packet)
        except:
            return HornetProcessingResult(HornetProcessingResult.Type.INVALID)
        if not sphinx_processing_result.is_to_forward():
            return HornetProcessingResult(HornetProcessingResult.Type.INVALID)
        (next_hop, processed_sphinx_packet) = sphinx_processing_result.result
        # Create new shared_key (forward secrecy) from a new Private
        tmp_private = Private()
        source_public = Public(sphinx_processing_result.source_pubkey)
        long_shared_key = tmp_private.get_shared_key(source_public)
        shared_key = long_shared_key[:SHARED_KEY_LENGTH]
        # Add a new FS to the FS payload
        new_fs = self.create_forwarding_segment(shared_key, next_hop,
                                                packet.expiration_time)
        tmp_pubkey = tmp_private.get_public().serialize()
        sphinx_shared_key = sphinx_processing_result.shared_key
        processed_fs_payload = self.add_fs_to_fs_payload(sphinx_shared_key,
                                                         new_fs,
                                                         tmp_pubkey,
                                                         packet.fs_payload)
        # Create the processed packet
        processed_packet = SetupPacket(packet.packet_type,
                                       packet.expiration_time,
                                       processed_sphinx_packet,
                                       processed_fs_payload,
                                       packet.max_hops).pack()
        return HornetProcessingResult(HornetProcessingResult.Type.FORWARD,
                                      packet_to_send=processed_packet)

    def process_data_packet(self, raw_packet):
        """
        Process an incoming Hornet data packet
        (:class:`hornet_packet.DataPacket`), and return an instance of class
        :class:`hornet_processing.HornetProcessingResult`.
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
