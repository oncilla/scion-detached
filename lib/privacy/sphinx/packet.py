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
from lib.privacy.sphinx.exception import PacketParsingException

# Default maximum number of hops on a path, including the destination
DEFAULT_MAX_HOPS = 8
DEFAULT_ADDRESS_LENGTH = 16 # Default size of a node's address/name in bytes
# Default size of a group element (for Diffie-Hellman) in bytes
DEFAULT_GROUP_ELEM_LENGTH = 32
DEFAULT_PAYLOAD_LENGTH = 512 # Default size of the payload in bytes
MAC_SIZE = 32 # Size of a Message Authentication Code in bytes

DEFAULT_LOCALHOST_ADDRESS = b"0" * DEFAULT_ADDRESS_LENGTH


def compute_pernode_size(address_length=DEFAULT_ADDRESS_LENGTH):
    """
    Compute the size in bytes of the part of the header needed for each node.
    """
    return address_length + MAC_SIZE


def compute_blinded_header_size(max_hops=DEFAULT_MAX_HOPS,
              address_length=DEFAULT_ADDRESS_LENGTH):
    """
    Compute the size in bytes of the blinded header.
    """
    return compute_pernode_size(address_length) * max_hops

def compute_header_size(max_hops=DEFAULT_MAX_HOPS,
              address_length=DEFAULT_ADDRESS_LENGTH,
              group_elem_length=DEFAULT_GROUP_ELEM_LENGTH):
    """
    Compute the size in bytes of a header.
    """
    blinded_header_length = compute_blinded_header_size(max_hops,
                                                        address_length)
    return (group_elem_length + compute_pernode_size(address_length) +
            blinded_header_length)


class SphinxHeader(object):
    """
    Header for a Sphinx packet

    :ivar dh_pubkey_0: Diffie-Hellman key-half for the first node
    :vartype dh_pubkey_0: bytes
    :ivar mac_0: MAC for the first node
    :vartype mac_0: bytes
    :ivar blinded_header: Blinded header containing next hops and MACs
    :vartype blinded_header: bytes
    :ivar first_hop: address (name) of the first-hop node
    :vartype first_hop: int
    """

    def __init__(self, dh_pubkey_0, mac_0, blinded_header, first_hop=None):
        self.dh_pubkey_0 = dh_pubkey_0
        self.mac_0 = mac_0
        self.blinded_header = blinded_header
        self.first_hop = first_hop

    @classmethod
    def parse_bytes_to_header(cls, raw, max_hops=DEFAULT_MAX_HOPS,
              address_length=DEFAULT_ADDRESS_LENGTH,
              group_elem_length=DEFAULT_GROUP_ELEM_LENGTH):
        """
        Parses the raw data and creates a SphinxHeader.

        :param raw: raw header (in byte sequence)
        :type raw: bytes
        :param max_hops: maximum number of nodes on the path
        :type max_hops: int
        :param address_length: length of a node's address/name
        :type address_length: int
        :param group_elem_length: length of a group element (for DH)
        :type group_elem_length: int
        :returns: the newly-created SphinxHeader instance
        :rtype: :class:`SphinxHeader`
        """
        assert isinstance(raw, bytes)
        expected_length = compute_header_size(max_hops, address_length,
                                              group_elem_length)
        if len(raw) != expected_length:
            raise PacketParsingException("Header is expected to have length "
                                         + str(expected_length)
                                         + ", instead got " + str(len(raw)))
        index_mac_0 = group_elem_length
        index_blinded_header = index_mac_0 + MAC_SIZE

        dh_pubkey_0 = raw[0:index_mac_0]
        mac_0 = raw[index_mac_0:index_blinded_header]
        blinded_header = raw[index_blinded_header:]
        return SphinxHeader(dh_pubkey_0, mac_0, blinded_header)

    def pack(self):
        """
        Return the header as a byte sequence

        :returns: raw header (byte sequence)
        :rtype: bytes
        """
        return self.dh_pubkey_0 + self.mac_0 + self.blinded_header


class SphinxPacket(object):
    """
    Sphinx packet, composed of a SphinxHeader and a payload.

    :ivar header: the header of the SphinxPacket
    :vartype header: :class:`SphinxHeader`
    :ivar payload: the payload of the SphinxPacket
    :vartype payload: bytes
    """

    def __init__(self, header, payload):
        assert isinstance(header, SphinxHeader)
        assert isinstance(payload, bytes)
        self.header = header
        self.payload = payload

    @classmethod
    def parse_bytes_to_packet(cls, raw, max_hops=DEFAULT_MAX_HOPS,
              address_length=DEFAULT_ADDRESS_LENGTH,
              group_elem_length=DEFAULT_GROUP_ELEM_LENGTH,
              payload_length=DEFAULT_PAYLOAD_LENGTH):
        """
        Parses the raw data and creates a SphinxPacket.

        :param raw: raw packet (in byte sequence)
        :type raw: bytes
        :param max_hops: maximum number of nodes on the path
        :type max_hops: int
        :param address_length: length of a node address (name)
        :type address_length: int
        :param group_elem_length: length of a group element (for Diffie-Hellman)
        :type group_elem_length: int
        :param payload_length: length of the payload
        :type payload_length: int
        :returns: the newly-created SphinxPacket instance
        :rtype: :class:`SphinxPacket`
        """
        assert isinstance(raw, bytes)
        expected_header_length = compute_header_size(max_hops, address_length,
                                                     group_elem_length)
        expected_packet_length = expected_header_length + payload_length
        if len(raw) != expected_packet_length:
            raise PacketParsingException("Packet is expected to have length "
                                         + str(expected_packet_length)
                                         + ", instead got " + str(len(raw)))
        raw_header = raw[0:expected_header_length]
        header = SphinxHeader.parse_bytes_to_header(
            raw_header,max_hops,address_length, group_elem_length)
        payload = raw[expected_header_length:]
        return SphinxPacket(header, payload)

    def pack(self):
        """
        Return the packet as a byte sequence

        :returns: raw packet (byte sequence)
        :rtype: bytes
        """
        return self.header.pack() + self.payload


