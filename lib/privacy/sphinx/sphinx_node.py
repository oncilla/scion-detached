"""
:mod:`sphinx_node` --- Sphinx node
==================================

This module defines the Sphinx node, main processing unit
of the Sphinx protocol.

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
from lib.privacy.sphinx.packet import SphinxPacket, MAC_SIZE,\
    compute_pernode_size, SphinxHeader
from lib.privacy.sphinx.packet import DEFAULT_MAX_HOPS,\
    DEFAULT_ADDRESS_LENGTH, DEFAULT_GROUP_ELEM_LENGTH, DEFAULT_PAYLOAD_LENGTH
from lib.privacy.common.exception import PacketParsingException
from curve25519.keys import Private, Public
from lib.privacy.sphinx.sphinx_crypto_util import verify_mac, derive_mac_key,\
    derive_stream_key, stream_cipher_decrypt, derive_prp_key,\
    compute_blinding_private, BLOCK_SIZE, pad_to_block_multiple, pad_to_length
from lib.crypto.prp import prp_decrypt, prp_encrypt


class ProcessingResult(object):
    """
    Result of the processing of a :class:`SphinxPacket`

    :ivar result_type: the type of the result
    :vartype result_type: :class:`ProcessingResult.Type`
    :ivar result: the result of the processing. The format depends on the type:
        - if the type is FORWARD, it is (next_hop, packet);
        - if the type is AT_DESTINATION, it is payload_message;
        - if the type is DROP, it is None or error_message.
    :vartype result: tuple or string or bytes
    """

    class Type(object):
        """
        Type of the result of the processing of a :class:`SphinxPacket`

        :ivar FORWARD: the packet should be forwarded
        :ivar AT_DESTINATION: the packet has reached its destination
        :ivar DROP: the packet is invalid and should be dropped
        """
        FORWARD = 0
        AT_DESTINATION = 1
        DROP = 2

    def __init__(self, result_type, result=None, reply_id=None,
                 shared_key=None, source_pubkey=None):
        self.result_type = result_type
        self.result = result
        #FIXME:Daniele: Add to documentation
        self.shared_key = shared_key
        self.source_pubkey = source_pubkey
        #FIXME:Daniele: The reply_id attribute was added for the case of
        # incoming replies, where a source needs to be able to recognize what
        # reply it received. This id can be e.g. the last dh_pubkey, that the
        # source receives, since this value is returned by compute_shared_keys
        self.reply_id = reply_id

    def is_failure(self):
        """
        Returns True if the processed packet was invalid, False otherwise
        """
        return self.result_type == ProcessingResult.Type.DROP

    def is_at_destination(self):
        """
        Returns True if the processed packet has reached the destination,
        False otherwise
        """
        return self.result_type == ProcessingResult.Type.AT_DESTINATION

    def is_to_forward(self):
        """
        Returns True if the processed packet should be forwarded,
        False otherwise
        """
        return self.result_type == ProcessingResult.Type.FORWARD


class SphinxNode(object):
    """
    A Sphinx mix node, able to process :class:`SphinxPacket`s.

    :ivar private: private key of the SphinxNode
    :vartype private: bytes or :class:`curve25519.keys.Private`
    :ivar public: public key of the SphinxNode
    :vartype public: bytes or :class:`curve25519.keys.Public`
    :ivar max_hops: maximum number of nodes on the path
    :vartype max_hops: int
    :ivar address_length: length of a node address (name)
    :vartype address_length: int
    :ivar group_elem_length: length of a group element (for Diffie-Hellman)
    :vartype group_elem_length: int
    :ivar payload_length: length of the payload
    :vartype payload_length: int
    """

    def __init__(self, private_key, public_key=None):
        assert private_key is not None
        if not isinstance(private_key, Private):
            assert isinstance(private_key, bytes)
            self._private = Private(raw=private_key)
        else:
            self._private = private_key
        self._public = self._private.get_public()
        if public_key is not None:
            assert isinstance(public_key, bytes)
            assert self.public.serialize() == public_key, ("the provided "
                "public and private keys do not match")
        self.max_hops = DEFAULT_MAX_HOPS
        self.address_length = DEFAULT_ADDRESS_LENGTH
        self.group_elem_length = DEFAULT_GROUP_ELEM_LENGTH
        self.payload_length = DEFAULT_PAYLOAD_LENGTH

    @property
    def private(self):
        """
        Getter for private property
        """
        return self._private

    @private.setter
    def private(self, new_private):
        """
        Setter for private property
        """
        assert new_private is not None
        if not isinstance(new_private, Private):
            assert isinstance(new_private, bytes)
            self._private = Private(raw=new_private)
        else:
            self._private = new_private
        self._public = self._private.get_public()

    @property
    def public(self):
        """
        Getter for public property
        """
        return self._public

    @public.setter
    def public(self):
        """
        Setter for public property (setting not allowed).
        """
        raise TypeError("Cannot assign directly to public property, "
                        "assign to private property instead")

    def get_localhost_address(self):
        """
        Return the byte sequence representing the localhost address
        """
        return b"0" * self.address_length

    def get_packet_processing_result(self, packet):
        """
        Process a Sphinx packet returning a :class:`ProcessingResult` instance.

        :param packet: a Sphinx packet (can be parsed or not)
        :type packet: bytes or :class:`SphinxPacket`
        :returns: a :class:`ProcessingResult` instance with the result
            of the processing of the input packet
        :rtype: :class:`ProcessingResult`
        """
        if not isinstance(packet, SphinxPacket):
            assert isinstance(packet, bytes)
            try:
                packet = SphinxPacket.parse_bytes_to_packet(packet)
            except PacketParsingException:
                return ProcessingResult(ProcessingResult.Type.DROP)
        header = packet.header
        if not isinstance(self.private, Private):
            private = Private(raw=self.private)
        else:
            private = self.private
        shared_key = private.get_shared_key(Public(header.dh_pubkey_0))
        if not verify_mac(derive_mac_key(shared_key), header.blinded_header,
                          header.mac_0):
            return ProcessingResult(ProcessingResult.Type.DROP)

        pad_size = compute_pernode_size(self.address_length)
        stream_key = derive_stream_key(shared_key)
        padded_blinded_header = header.blinded_header + b'\0'*pad_size
        decrypted_header = stream_cipher_decrypt(stream_key,
                                                 padded_blinded_header)
        payload = prp_decrypt(derive_prp_key(shared_key), packet.payload)
        next_hop = decrypted_header[:self.address_length]
        if next_hop == self.get_localhost_address():
            return ProcessingResult(ProcessingResult.Type.AT_DESTINATION,
                                    result=payload,
                                    shared_key=shared_key,
                                    source_pubkey=header.dh_pubkey_0)
        # Construct the next header
        next_mac = decrypted_header[self.address_length:
                                    self.address_length+MAC_SIZE]
        next_blinded_header = decrypted_header[self.address_length+MAC_SIZE:]
        blinding_factor = compute_blinding_private(header.dh_pubkey_0,
                                                   shared_key)
        next_dh_pubkey = \
            blinding_factor.get_shared_public(Public(header.dh_pubkey_0))
        next_header = SphinxHeader(next_dh_pubkey, next_mac,
                                   next_blinded_header, next_hop)
        # Construct the next packet
        next_packet = SphinxPacket(next_header, payload)
        return ProcessingResult(ProcessingResult.Type.FORWARD,
                                result=(next_hop, next_packet),
                                shared_key=shared_key,
                                source_pubkey=header.dh_pubkey_0)

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
        assert isinstance(message, bytes)
        assert isinstance(shared_key, bytes)
        assert isinstance(header, SphinxHeader)
        # Since the padding requires at least two bytes, the message should be
        # strictly smaller (by at least two bytes) than the payload length.
        assert len(message) < self.payload_length-1
        payload = pad_to_block_multiple(
            pad_to_length(message, self.payload_length - 1), BLOCK_SIZE)
        prp_key = derive_prp_key(shared_key)
        payload = prp_encrypt(prp_key, payload)
        return SphinxPacket(header, payload)


def test():
    private = Private()
    node = SphinxNode(private)
    new_private = Private()
    node.private = new_private
    assert node.public.serialize() == new_private.get_public().serialize()
    

if __name__ == '__main__':
    test()

