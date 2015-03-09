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
    compute_pernode_size, SphinxHeader, SphinxPacket
from lib.privacy.sphinx.sphinx_crypto_util import stream_cipher_decrypt,\
    derive_stream_key, derive_mac_key, stream_cipher_encrypt, compute_mac,\
    derive_prp_key, pad_to_length
import os
from lib.crypto.prp import prp_encrypt, prp_decrypt


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

#     def __init__(self, public_key, private_key):
#         SphinxNode.__init__(self, public_key, private_key)

    def _construct_final_header(self, stream_keys, number_of_hops):
        """
        Construct the header as it will be decrypted by the destination.
        """
        blinded_header_size = compute_blinded_header_size(self.max_hops,
                                                          self.address_length)
        pad_size = compute_pernode_size(self.address_length)

        # Create filler string
        long_filler = b"0" * (blinded_header_size + pad_size)
        for stream_key in stream_keys:
            long_filler = stream_cipher_decrypt(stream_key, long_filler)
        filler_length = pad_size * number_of_hops
        filler = long_filler[-filler_length:]

        # Create random pad: in the original Sphinx paper a zero-padding
        # is used instead, which leaks the path length to the destination
        random_pad = os.urandom(blinded_header_size - len(filler)
                                - self.address_length)
        return self.get_localhost_address() + random_pad + filler

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
        for address in next_hops:
            assert isinstance(address, bytes)
            assert len(address) == self.address_length
        assert isinstance(dh_pubkey_0, bytes)
        assert len(dh_pubkey_0) == 32

        # Derive the necessary keys from the shared keys
        stream_keys = [derive_stream_key(k) for k in shared_keys]
        mac_keys = [derive_mac_key(k) for k in shared_keys]

        # Create the blinded header by reversing the decryption steps done
        # at each hop by the nodes, starting by the destination's decryption
        # of the blinded header it will receive.
        pad_size = compute_pernode_size(self.address_length)
        decrypted_header = \
            self._construct_final_header(stream_keys, len(next_hops))
        reversed_lists = zip(reversed(next_hops), reversed(stream_keys),
                             reversed(mac_keys))
        for address, stream_key, mac_key in reversed_lists:
            padded_blinded_header = \
                stream_cipher_encrypt(stream_key, decrypted_header)
            assert padded_blinded_header[-pad_size:] == b"0" * pad_size
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
        # Since the padding requires at least one byte, the message should be
        # strictly smaller (by at least one byte) than the payload length.
        assert len(message) < self.payload_length
        payload = pad_to_length(message, self.payload_length)
        prp_keys = [derive_prp_key(k) for k in shared_keys]
        for prp_key in reversed(prp_keys):
            payload = prp_encrypt(prp_key, payload)
        return SphinxPacket(header, payload)

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
        payload = pad_to_length(message, self.payload_length)
        prp_key = derive_prp_key(shared_key)
        payload = prp_encrypt(prp_key, payload)
        return SphinxPacket(header, payload)


def main():
    pass

if __name__ == "__main__":
    main()

