# Copyright 2014 ETH Zurich

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`packet` --- Sphinx packet format
======================================

This module defines the Sphinx packet format.

"""
#TODO/dasoni: add Sphinx reference


DEFAULT_MAX_HOPS = 8 # Default maximum number of hops on a path
DEFAULT_ADDRESS_LENGTH = 16 # Default size of a node's address/name in bytes
# Default size of a group element (for Diffie-Hellman) in bytes
DEFAULT_GROUP_ELEM_LENGTH = 32
DEFAULT_PAYLOAD_LENGTH = 512 # Default size of the payload in bytes
MAC_SIZE = 16 # Size of a Messge Authentication Code in bytes


def compute_header_size(max_hops=DEFAULT_MAX_HOPS,
              address_length=DEFAULT_ADDRESS_LENGTH,
              group_elem_length=DEFAULT_GROUP_ELEM_LENGTH):
    """
    Compute the size in bytes of a header.

    :param max_hops: maximum number of nodes on the path
    :type max_hops: int
    :param address_length: length of a node's address/name
    :type address_length: int
    :param group_elem_length: length of a group element (for Diffie-Hellman)
    :type group_elem_length: int
    """
    blinded_header_length = (address_length + MAC_SIZE) * max_hops
    return group_elem_length + MAC_SIZE + blinded_header_length


class SphinxHeader(object):
    """
    Header for a Sphinx packet

    :ivar dh_keyhalf_0: Diffie-Hellman key-half for the first node
    :vartype dh_keyhalf_0: bytes
    :ivar mac_0: MAC for the first node
    :vartype mac_0: bytes
    :ivar blinded_header: Blinded header containing next hops and MACs
    :vartype blinded_header: bytes
    :ivar first_hop: address (name) of the first-hop node
    :vartype first_hop: int
    """

    def __init__(self, dh_keyhalf_0, mac_0, blinded_header, first_hop=None):
        self.dh_keyhalf_0 = dh_keyhalf_0
        self.mac_0 = mac_0
        self.blinded_header = blinded_header
        self.first_hop = first_hop

    @classmethod
    def construct_header(cls, shared_keys, next_hops, dh_keyhalf_0=None,
                         max_hops=DEFAULT_MAX_HOPS):
        """
        Constructs a new SphinxHeader

        :param shared_keys: List of keys shared with each node on the path
        :type shared_keys: list
        :param next_hops: list of node names (addresses) on the path
        :type next_hops: list
        :param dh_keyhalf_0: Diffie-Hellman key-half for the first node
        :type dh_keyhalf_0: bytes
        :param max_hops: maximum number of nodes on the path
        :type max_hops: int
        :returns: the newly-created SphinxHeader instance
        :rtype: :class:`SphinxHeader`
        """
        pass #TODO/daniele: implement this method

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
        :param group_elem_length: length of a group element (for Diffie-Hellman)
        :type group_elem_length: int
        :returns: the newly-created SphinxHeader instance
        :rtype: :class:`SphinxHeader`
        """
        assert isinstance(raw, bytes)
        expected_length = compute_header_size(max_hops, address_length,
                                              group_elem_length)
        if len(raw) != expected_length:
            raise Exception() #TODO/Daniele: Create specific exception
        index_mac_0 = group_elem_length
        index_blinded_header = index_mac_0 + MAC_SIZE
        dh_keyhalf_0 = raw[0:index_mac_0]
        mac_0 = raw[index_mac_0:index_blinded_header]
        blinded_header = raw[index_blinded_header:]
        return SphinxHeader(dh_keyhalf_0, mac_0, blinded_header)

    def pack(self):
        """
        Return the header as a byte sequence

        :returns: raw header (byte sequence)
        :rtype: bytes
        """
        return self.dh_keyhalf_0 + self.mac_0 + self.blinded_header


class SphinxPacket(object):
    """
    Sphinx packet, composed of a SphinxHeader and a payload.

    :ivar header: the header of the SphinxPacket
    :vartype header: :class:`SphinxHeader`
    :ivar payload: the payload of the SphinxPacket
    :vartype payload: bytes
    """

    def __init__(self, header, payload):
        self.header = header
        self.payload = payload

    @classmethod
    def construct_forward_packet(cls, message, shared_keys, header):
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

    @classmethod
    def construct_reply_packet(cls, message, shared_key, header):
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
        :type max_hops: int
        :param group_elem_length: length of a group element (for Diffie-Hellman)
        :type max_hops: int
        :param payload_length: length of the payload
        :type max_hops: int
        :returns: the newly-created SphinxPacket instance
        :rtype: :class:`SphinxPacket`
        """
        assert isinstance(raw, bytes)
        expected_header_length = compute_header_size(max_hops, address_length,
                                                     group_elem_length)
        if len(raw) != (expected_header_length + payload_length):
            raise Exception() #TODO/Daniele: Create specific exception
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


