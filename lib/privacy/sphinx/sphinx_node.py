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
from lib.privacy.sphinx.exception import PacketParsingException
from curve25519.keys import Private, Public
from lib.privacy.sphinx.sphinx_crypto_util import verify_mac, derive_mac_key,\
    derive_stream_key, stream_cipher_decrypt, blind_dh_key, derive_prp_key,\
    get_secret_for_blinding, BLOCK_SIZE, pad_to_block_multiple, pad_to_length
from lib.crypto.prp import prp_decrypt, prp_encrypt


class ProcessingResult(object):
    """
    Result of the processing of a :class:`SphinxPacket`

    :ivar type: the type of the result
    :vartype type: :class:`ProcessingResult.ResultType`
    :ivar result: the result of the processing. The format depends on the type:
        - if the type is FORWARD, it is (next_hop, packet);
        - if the type is AT_DESTINATION, it is payload_message;
        - if the type is DROP, it is None or error_message.
    :vartype result: tuple or string or bytes
    """

    class ResultType(object):
        """
        Type of the result of the processing of a :class:`SphinxPacket`

        :ivar FORWARD: the packet should be forwarded
        :ivar AT_DESTINATION: the packet has reached its destination
        :ivar DROP: the packet is invalid and should be dropped
        """
        FORWARD = 0
        AT_DESTINATION = 1
        DROP = 2

    def __init__(self, result_type, result=None):
        self.result_type = result_type
        self.result = result

    def is_failure(self):
        """
        Returns True if the processed packet was invalid, False otherwise
        """
        return self.result_type == ProcessingResult.ResultType.DROP

    def is_at_destination(self):
        """
        Returns True if the processed packet has reached the destination,
        False otherwise
        """
        return self.result_type == ProcessingResult.ResultType.AT_DESTINATION

    def is_to_forward(self):
        """
        Returns True if the processed packet should be forwarded,
        False otherwise
        """
        return self.result_type == ProcessingResult.ResultType.FORWARD


class SphinxNode(object):
    """
    A Sphinx mix node, able to process :class:`SphinxPacket`s.

    :ivar private_key: private key of the SphinxNode
    :vartype private_key: bytes or :class:`curve25519.keys.Private`
    :ivar public_key: public key of the SphinxNode
    :vartype public_key: bytes
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
                        "assing to private property instead")

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
                return ProcessingResult(ProcessingResult.ResultType.DROP)
        header = packet.header
        if not isinstance(self.private, Private):
            private = Private(raw=self.private)
        else:
            private = self.private
        shared_key = private.get_shared_key(Public(header.dh_pubkey_0))
        if not verify_mac(derive_mac_key(shared_key), header.blinded_header,
                          header.mac_0):
            return ProcessingResult(ProcessingResult.ResultType.DROP)

        pad_size = compute_pernode_size(self.address_length)
        stream_key = derive_stream_key(shared_key)
        padded_blinded_header = header.blinded_header + b'\0'*pad_size
        decrypted_header = stream_cipher_decrypt(stream_key,
                                                 padded_blinded_header)
        payload = prp_decrypt(derive_prp_key(shared_key), packet.payload)
        next_hop = decrypted_header[:self.address_length]
        if next_hop == self.get_localhost_address():
            return ProcessingResult(ProcessingResult.ResultType.AT_DESTINATION,
                                    payload)
        # Construct the next header
        next_mac = decrypted_header[self.address_length:
                                    self.address_length+MAC_SIZE]
        next_blinded_header = decrypted_header[self.address_length+MAC_SIZE:]
        secret_for_blinding = get_secret_for_blinding(header.dh_pubkey_0,
                                                      shared_key)
        next_dh_pubkey = blind_dh_key(header.dh_pubkey_0, secret_for_blinding)
        next_header = SphinxHeader(next_dh_pubkey, next_mac,
                                   next_blinded_header, next_hop)
        # Construct the next packet
        next_packet = SphinxPacket(next_header, payload)
        return ProcessingResult(ProcessingResult.ResultType.FORWARD,
                                (next_hop, next_packet))

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
    node.private = b'1'*32
    

if __name__ == '__main__':
    test()

