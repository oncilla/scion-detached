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
from lib.privacy.sphinx.sphinx_node import SphinxNode, ProcessingResult
from lib.privacy.sphinx.packet import compute_blinded_header_size,\
    compute_pernode_size, SphinxHeader, SphinxPacket
from lib.privacy.sphinx.sphinx_crypto_util import stream_cipher_decrypt,\
    derive_stream_key, derive_mac_key, stream_cipher_encrypt, compute_mac,\
    derive_prp_key, pad_to_length, pad_to_block_multiple,\
    compute_blinding_private, remove_block_pad,\
    remove_length_pad, verify_mac
import os
from lib.crypto.prp import prp_encrypt, BLOCK_SIZE, prp_decrypt
from curve25519.keys import Private, Public
import curve25519.keys
from lib.privacy.sphinx.exception import PacketParsingException


def compute_shared_keys(source_private, nodes_pubkeys):
    """
    Compute the shared keys between the source, whose temporary private key
    is given as input, and the nodes the public keys of which are in the
    list nodes_pubkeys. This function also returns the last DH public key
    as it is received by the last hop: this is useful in reply packets so that
    the source may recognize a reply without having do a DH handshake.
    """
    shared_keys = []
    blinding_factors = []
    source_pubkey = source_private.get_public()

    for node_pubkey in nodes_pubkeys:
        if not isinstance(node_pubkey, Public):
            node_pubkey = Public(node_pubkey)
        tmp_pubkey = node_pubkey
        for bf in blinding_factors:
            tmp_pubkey = bf.get_shared_public(tmp_pubkey)
        shared_key = source_private.get_shared_key(tmp_pubkey)
        shared_keys.append(shared_key)
        blinding_factors.append(compute_blinding_private(source_pubkey,
                                                         shared_key))
        last_source_pubkey = source_pubkey
        source_pubkey = blinding_factors[-1].get_shared_public(source_pubkey)
    return shared_keys, blinding_factors, last_source_pubkey


class SphinxEndHost(SphinxNode):
    """
    A Sphinx end host (source), which can create new Sphinx packets, reply
    headers and reply packets from reply headers.

    :ivar private_key: private key of the SphinxEndHost. In case of the source
        this value is not used, so it should be set to the temporary private
        key being used for the packet that is being sent.
    :vartype private_key: bytes or :class:`curve25519.keys.Private`
    :ivar public_key: public key of the SphinxEndHost. In case of the source
        this value is not used, so it should be set to the temporary public
        key being used for the packet that is being sent.
    :vartype public_key: bytes
    :ivar max_hops: maximum number of nodes on the path
    :vartype max_hops: int
    :ivar address_length: length of a node address (name)
    :vartype address_length: int
    :ivar group_elem_length: length of a group element (for Diffie-Hellman)
    :vartype group_elem_length: int
    :ivar payload_length: length of the payload
    :vartype payload_length: int
    :ivar expected_replies: dictionary containing as keys the dh public keys
        corresponding to reply headers created, and as value for each key a
        tuple of the form (shared_keys, destination_shared_key), where
        shared_keys is the list of shared keys with all nodes on the backward
        path (the last key is just a secrect key known only to the source),
        and destination_shared_key is the key shared between the source and
        the destination (the sender of the packet).
    :vartype expected_replies: dict
    """
    #TODO/Daniele: check whether it is correct to specify the instance
    #    attributes "inherited" from the superclass

    def __init__(self, private_key, public_key=None):
        SphinxNode.__init__(self, private_key, public_key)
        self.expected_replies = dict()

    def add_expected_reply(self, dh_pubkey, shared_keys,
                           destination_shared_key):
        """
        Add an entry to the expected_replies dictionary to be able to correctly
        process the replies when they arrive.

        :param dh_pubkey: the dh_pubkey_0 of the SphinxHeader as seen once
            the source is reached (after having been blinded by all the hops
            on the backward path)
        :type dh_pubkey: bytes or :class:`curve25519.keys.Public`
        :param shared_keys: The keys shared between the source and all the
            nodes on the backward path (the last key is just a secrect key
            known only to the source)
        :type shared_keys: list
        :param destination_shared_key: the key shared between the source and
            the destination (the sender of the packet)
        :type destination_shared_key: bytes
        """
        if isinstance(dh_pubkey, Public):
            dh_pubkey = dh_pubkey.serialize()
        assert isinstance(shared_keys, list)
        for k in shared_keys:
            assert isinstance(k, bytes)
        assert isinstance(destination_shared_key, bytes)
        self.expected_replies[dh_pubkey] = (shared_keys,
                                            destination_shared_key)

    def _construct_final_header(self, stream_keys, number_of_hops,
                                last_address_field=None):
        """
        Construct the header as it will be decrypted by the destination.
        """
        blinded_header_size = compute_blinded_header_size(self.max_hops,
                                                          self.address_length)
        pad_size = compute_pernode_size(self.address_length)
        complete_header_size = blinded_header_size + pad_size

        # Create filler string
        long_filler = b'\0' * complete_header_size
        for stream_key in stream_keys:
            long_filler = long_filler[pad_size:] + b'\0'*pad_size
            long_filler = stream_cipher_decrypt(stream_key, long_filler)
        filler_length = pad_size * number_of_hops
        filler = long_filler[-filler_length:]

        # Create random pad: in the original Sphinx paper a zero-padding
        # is used instead, which leaks the path length to the destination
        random_pad = os.urandom(complete_header_size - len(filler)
                                - self.address_length)
        if last_address_field is None:
            address_field = self.get_localhost_address()
        else:
            address_field = last_address_field
        return address_field + random_pad + filler

    def construct_header(self, shared_keys, dh_pubkey_0, next_hops,
                         last_address_field=None):
        """
        Constructs a new SphinxHeader, given the keys (use
        :func:`compute_shared_keys` to compute them).

        :param shared_keys: List of keys shared with each node on the path
        :type shared_keys: list
        :param dh_pubkey_0: temporary Diffie-Hellman public key (of the source)
            for the first node
        :type dh_pubkey_0: bytes
        :param next_hops: list of node names (addresses) on the path
        :type next_hops: list
        :param last_address_field: the address field obtained by the last
            hop (destination) when decrypting the blinded header. This is
            meant to be used as an identifier (e.g. for reply packets).
            If not provided, the last address will be set to the localhost
            address: for forward packets, this allows the destination to
            check that it is the intended recipient of the packet.
        :type last_address_field: bytes
        :returns: the newly-created SphinxHeader instance
        :rtype: :class:`SphinxHeader`
        """
        assert len(shared_keys) < self.max_hops
        for k in shared_keys:
            assert isinstance(k, bytes)
        assert len(next_hops) == len(shared_keys)
        for address in next_hops:
            assert isinstance(address, bytes)
            assert len(address) == self.address_length
        assert isinstance(dh_pubkey_0, bytes)
        assert len(dh_pubkey_0) == 32
        if last_address_field is not None:
            assert isinstance(last_address_field, bytes)
            assert len(last_address_field) == self.address_length

        # Derive the necessary keys from the shared keys
        stream_keys = [derive_stream_key(k) for k in shared_keys]
        mac_keys = [derive_mac_key(k) for k in shared_keys]

        # Create the blinded header by reversing the decryption steps done
        # at each hop by the nodes, starting by the destination's decryption
        # of the blinded header it will receive.
        pad_size = compute_pernode_size(self.address_length)
        decrypted_header = self._construct_final_header(stream_keys,
                                                        len(next_hops),
                                                        last_address_field)
        reversed_lists = zip(reversed(next_hops), reversed(stream_keys),
                             reversed(mac_keys))
        for address, stream_key, mac_key in reversed_lists:
            padded_blinded_header = \
                stream_cipher_encrypt(stream_key, decrypted_header)
            assert padded_blinded_header[-pad_size:] == b'\0' * pad_size
            blinded_header = padded_blinded_header[:-pad_size]
            mac = compute_mac(mac_key, blinded_header)
            decrypted_header = address + mac + blinded_header
        # Note that the last assignment to decrypted_header in the previous
        # for-loop is superfluous for the last iteration (it is what the
        # source would "decrypt").
        return SphinxHeader(dh_pubkey_0, mac, blinded_header, next_hops[0])

    def construct_forward_packet(self, message, shared_keys, header):
        """
        Constructs a new SphinxPacket to be sent by the source.
        It first constructs the header, then onion-encrypts the payload.

        :param message: the message to be sent as payload
        :type message: bytes
        :param shared_keys: List of keys shared with each node on the path
        :type shared_keys: list
        :param header: the reply SphinxHeader
        :type header: :class:`SphinxPacket`
        :returns: the newly-created SphinxPacket instance
        :rtype: :class:`SphinxPacket`
        """
        assert isinstance(message, bytes)
        for k in shared_keys:
            assert isinstance(k, bytes)
        assert isinstance(header, SphinxHeader)
        # Since the padding requires at least two bytes, the message should be
        # strictly smaller (by at least two bytes) than the payload length.
        assert len(message) < self.payload_length-1
        payload = pad_to_block_multiple(
            pad_to_length(message, self.payload_length - 1), BLOCK_SIZE)
        prp_keys = [derive_prp_key(k) for k in shared_keys]
        for prp_key in reversed(prp_keys):
            payload = prp_encrypt(prp_key, payload)
        return SphinxPacket(header, payload)

    def process_incoming_reply(self, packet, allow_reuse=False):
        """
        Process a Sphinx packet expected to be a reply, as a source.

        :param packet: a Sphinx packet (can be parsed or not)
        :type packet: bytes or :class:`SphinxPacket`
        :param allow_reuse: If set to true, the header is not removed from the
            dictionary of expected replies, allowing future packets carrying
            the same header.
        :returns: a :class:`ProcessingResult` instance with the result
            of the processing of the input packet. The result type will either
            be DROP or AT_DESTINATION.
        :rtype: :class:`ProcessingResult`
        """
        if not isinstance(packet, SphinxPacket):
            assert isinstance(packet, bytes)
            try:
                packet = SphinxPacket.parse_bytes_to_packet(packet)
            except PacketParsingException:
                return ProcessingResult(ProcessingResult.Type.DROP)
        header = packet.header
        if header.dh_pubkey_0 not in self.expected_replies:
            return ProcessingResult(ProcessingResult.Type.DROP)
        shared_keys, destination_shared_key = \
            self.expected_replies[header.dh_pubkey_0]
        source_key = shared_keys[-1]
        if not verify_mac(derive_mac_key(source_key), header.blinded_header,
                          header.mac_0):
            return ProcessingResult(ProcessingResult.Type.DROP)
        if not allow_reuse:
            del self.expected_replies[header.dh_pubkey_0]
        payload = packet.payload
        for prp_key in reversed([derive_prp_key(key)
                                     for key in shared_keys[:-1]]):
            payload = prp_encrypt(prp_key, payload)
        payload = prp_decrypt(derive_prp_key(destination_shared_key), payload)
        return ProcessingResult(ProcessingResult.Type.AT_DESTINATION,
                                payload)

    @staticmethod
    def get_message_from_payload(payload):
        """
        Obtain original message from payload (remove padding.
        """
        assert isinstance(payload, bytes)
        return remove_length_pad(remove_block_pad(payload))


def test():
    private = Private()
    end_host = SphinxEndHost(private)
    shared_keys = [b'1'*32, b'2'*32, b'3'*32]
    dh_pubkey_0 = b'a'*32
    next_hops = [b'x'*16, b'y'*16, b'z'*16]
    header = end_host.construct_header(shared_keys, dh_pubkey_0, next_hops)

    end_host.construct_forward_packet(b'1234', shared_keys, header)
    end_host.construct_reply_packet(b'5678', shared_keys[-1], header)


def test_routing():
    # Fake key for the source as the last node, used in replies. This
    # key may be always the same, but in any case it does not need to be
    # known to any other party
    source_private = Private()
    node_1_private = Private()
    node_2_private = Private()
    node_3_private = Private()

    source = SphinxEndHost(source_private)
    source_pubkey = source.public
    node_1 = SphinxNode(node_1_private)
    node_2 = SphinxNode(node_2_private)
    node_3 = SphinxEndHost(node_3_private) # Destination

    ## Forward packet ##
    nodes_privates = [node_1_private, node_2_private, node_3_private]
    nodes_pubkeys = [p.get_public() for p in nodes_privates]
    tmp_initial_private = Private()
    shared_keys, _, _= compute_shared_keys(tmp_initial_private, nodes_pubkeys)

    tmp_initial_pubkey = tmp_initial_private.get_public().serialize()
    next_hops = [b'1'*16, b'2'*16, b'3'*16]
    message = b"Test Message"
    header = source.construct_header(shared_keys, tmp_initial_pubkey,
                                     next_hops)
    packet = source.construct_forward_packet(message, shared_keys, header)
    raw_packet = packet.pack()

    # Node 1
    result = node_1.get_packet_processing_result(raw_packet)
    assert result.is_to_forward()
    assert result.result[0] == next_hops[1]
    raw_packet = result.result[1].pack()

    # Node 2
    result = node_2.get_packet_processing_result(raw_packet)
    assert result.is_to_forward()
    assert result.result[0] == next_hops[2]
    raw_packet = result.result[1].pack()

    # Node 3 - Destination
    result = node_3.get_packet_processing_result(raw_packet)
    assert result.is_at_destination()
    assert node_3.get_message_from_payload(result.result) == message

    ## Reply packet ##
    # Remove previous last hop (destination), reverse the order of the nodes
    # and add the public key of the source as last node.
    nodes_pubkeys = nodes_pubkeys[-2::-1]
    nodes_pubkeys.append(source_pubkey)
    # reply_source_private: temporary private key for the reply packet
    tmp_initial_private = Private()
    shared_keys, _, final_dh_pubkey = compute_shared_keys(tmp_initial_private,
                                                          nodes_pubkeys)
    source_self_shared_key = shared_keys[-1]
    dest_shared_key = tmp_initial_private.get_shared_key(node_3.public)

    tmp_initial_pubkey = tmp_initial_private.get_public().serialize()
    next_hops = [b'2'*16, b'1'*16, b'source_address00']
    header = source.construct_header(shared_keys, tmp_initial_pubkey,
                                     next_hops)
    source.add_expected_reply(final_dh_pubkey, shared_keys, dest_shared_key)

    # Node 3 - Destination
    message = b"Test Reply Message"
    packet = node_3.construct_reply_packet(message, dest_shared_key, header)
    raw_packet = packet.pack()

    # Node 2
    result = node_2.get_packet_processing_result(raw_packet)
    assert result.is_to_forward()
    assert result.result[0] == next_hops[1]
    raw_packet = result.result[1].pack()

    # Node 1
    result = node_1.get_packet_processing_result(raw_packet)
    assert result.is_to_forward()
    assert result.result[0] == next_hops[2]
    raw_packet = result.result[1].pack()

    # Source
    result = source.process_incoming_reply(raw_packet)
    assert result.is_at_destination()
    assert source.get_message_from_payload(result.result) == message

if __name__ == "__main__":
    test()
    test_routing()

