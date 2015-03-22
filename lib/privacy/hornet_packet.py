"""
:mod:`hornet_packet` --- HORNET packet format
=============================================

This module defines the packet format for HORNET's setup phase and data
transmission phase.

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

import lib.privacy.sphinx.packet as sphinx_packet_mod
from lib.privacy.sphinx.packet import SphinxHeader, SphinxPacket
from lib.privacy.common.exception import PacketParsingException
from lib.privacy.common.constants import DEFAULT_MAX_HOPS, MAC_SIZE,\
    GROUP_ELEM_LENGTH, DEFAULT_ADDRESS_LENGTH

MAX_HOPS_LENGTH = 1 # Number of bytes needed for the max_hops field
NONCE_LENGTH = 4 # Size of a nonce in bytes
# Length of the shared key between a source and a node
SHARED_KEY_LENGTH = 16
ROUTING_INFO_LENGTH = 16
TIMESTAMP_LENGTH = 4
FS_LENGTH = SHARED_KEY_LENGTH + ROUTING_INFO_LENGTH + TIMESTAMP_LENGTH
# Length of the payload of a DataPacket in bytes
DATA_PAYLOAD_LENGTH = 512


def compute_fs_payload_size(max_hops=DEFAULT_MAX_HOPS):
    """
    Compute the size in bytes of the fs payload
    """
    return (FS_LENGTH + MAC_SIZE + GROUP_ELEM_LENGTH) * max_hops


def compute_blinded_aheader_size(max_hops=DEFAULT_MAX_HOPS):
    """
    Compute the size in bytes of the blinded header (of the
    :class:`AnonymousHeader`)
    """
    return (FS_LENGTH + MAC_SIZE) * (max_hops - 1)


class HornetPacketType(object):
    """
    Hornet packet type
    """
    # _LEN is not a type, it indicates the length of a packet type in bytes
    _LEN = 2
    # Setup packet types, to be routed through Sphinx header.
    SETUP_FWD = 0
    SETUP_BWD = 1
    # Data transmission packet types, routed through A-headers
    DATA_FWD_SESSION = 8 # Packet providing the backward A-header to the dest.
    DATA_FWD = 9
    DATA_BWD = 10

    TYPES = (SETUP_FWD, SETUP_BWD, DATA_FWD, DATA_FWD_SESSION, DATA_BWD)
    for packet_type in TYPES:
        assert packet_type >= 0
        assert packet_type < 2 ** (8*_LEN)
    SETUP_TYPES = (SETUP_FWD, SETUP_BWD)
    DATA_TYPES = (DATA_FWD, DATA_FWD_SESSION, DATA_BWD)
    assert not set(SETUP_TYPES).intersection(DATA_TYPES)

    @classmethod
    def length(cls):
        """
        Return the length in bytes of a Hornet packet type
        """
        return cls._LEN

    @classmethod
    def from_bytes(cls, raw):
        """
        Parses the raw bytes to a packet type

        :returns: packet type
        :rtype: int
        """
        assert isinstance(raw, bytes)
        assert len(raw) == cls._LEN
        packet_type = int.from_bytes(raw, "big")
        if packet_type not in cls.TYPES:
            raise TypeError("packet type must be one of " + str(cls.TYPES))
        return packet_type

    @classmethod
    def to_bytes(cls, packet_type):
        """
        Return the packet type as a byte sequence

        :returns: raw packet type (byte sequence)
        :rtype: bytes
        """
        assert isinstance(packet_type, int)
        assert packet_type in cls.TYPES
        return packet_type.to_bytes(cls._LEN, "big")


def get_packet_type(raw_packet_or_header):
    """
    Get the type of a Hornet packet or header as byte sequence
    """
    assert isinstance(raw_packet_or_header, bytes)
    length = HornetPacketType.length()
    return HornetPacketType.from_bytes(raw_packet_or_header[:length])


class HornetPacket(object):
    """
    Abstact base class for all Hornet packets.
    """

    def pack(self):
        """
        Return the packet as a byte sequence

        :returns: raw packet (byte sequence)
        :rtype: bytes
        """
        raise NotImplementedError

    def get_type(self):
        """
        Return the type of the packet

        :rtype: :class:`HornetPacketType`
        """
        raise NotImplementedError

    def get_first_hop(self):
        """
        Return the first hop to which the packet should be forwarded,
        or None if it is not specified

        :rtype: bytes or NoneType
        """
        raise NotImplementedError


class SetupPacket(HornetPacket):
    """
    Packet of the setup phase.

    :ivar packet_type: Type of the packet must be one of the
        :class:`HornetPacketType`.SETUP_TYPES types.
    :vartype packet_type: int
    :ivar expiration_time: Timestamp indicating the expiration time
        of the session being constructed (as returned by :func:`time.time()`).
        The expiration time is used instead of a duration because Hornet
        does not have replay protection, so without timestamp a packet could be
        replayed forever (as long as the public keys of the nodes are valid).
        The assumption is that all the nodes and the sources have a weak time
        synchronization.
    :vartype expiration_time: int
    :ivar sphinx_packet: Sphinx packet made of the :class:`SphinxHeader`
        necessary to route the packet, and of a payload
    :vartype sphinx_packet: :class:`SphinxPacket`
    :ivar fs_payload: FS payload, containing all the FSes collected
    :vartype fs_payload: bytes
    :ivar first_hop: Address (routing information) of the first hop to which
        the packet should be sent to.
    :ivar first_hop: bytes
    :ivar max_hops: Maximum number of hops on the path
    :vartype max_hops: int
    """

    def __init__(self, packet_type, expiration_time, sphinx_packet,
                 fs_payload, first_hop=None, max_hops=DEFAULT_MAX_HOPS):
        assert isinstance(packet_type, int)
        assert isinstance(expiration_time, int)
        assert isinstance(sphinx_packet, SphinxPacket)
        assert isinstance(fs_payload, bytes)
        assert first_hop is None or isinstance(first_hop, bytes)
        assert isinstance(max_hops, int)
        if packet_type not in HornetPacketType.SETUP_TYPES:
            raise TypeError("expected setup type, one of " +
                            str(HornetPacketType.SETUP_TYPES))
        self.packet_type = packet_type
        self.max_hops = max_hops
        self.expiration_time = expiration_time
        self.sphinx_packet = sphinx_packet
        self.fs_payload = fs_payload
        self.first_hop = first_hop

    @classmethod
    def parse_bytes_to_packet(cls, raw, **kwargs):
        """
        Parses the raw data and creates a SetupPacket.

        :param raw: raw packet (in byte sequence)
        :type raw: bytes
        :param max_hops: maximum number of nodes on the path
        :type max_hops: int
        :param address_length: length of a node address (name)
        :type address_length: int
        :param group_elem_length: length of a group element, used in Sphinx
            (for Diffie-Hellman).
        :type group_elem_length: int
        :param payload_length: length of the payload
        :type payload_length: int
        :returns: the newly-created :class:`SetupPacket     instance
        :rtype: :class:`SetupPacket`
        """
        assert isinstance(raw, bytes)
        max_hops_index = HornetPacketType.length()
        timestamp_index = max_hops_index + MAX_HOPS_LENGTH
        sphinx_packet_index = timestamp_index + TIMESTAMP_LENGTH
        if len(raw) < sphinx_packet_index:
            raise PacketParsingException("Setup packet is too small")

        packet_type = HornetPacketType.from_bytes(raw[:max_hops_index])
        max_hops = int.from_bytes(raw[max_hops_index:timestamp_index], "big")
        expiration_time = int.from_bytes(raw[timestamp_index:
                                             sphinx_packet_index], "big")

        fs_payload_index = -compute_fs_payload_size(max_hops=max_hops)
        if len(raw) < sphinx_packet_index + (-fs_payload_index):
            raise PacketParsingException("Setup packet is too small")
        kwargs["max_hops"] = max_hops
        sphinx_packet = SphinxPacket.parse_bytes_to_packet(
            raw[sphinx_packet_index:fs_payload_index], **kwargs)
        fs_payload = raw[fs_payload_index:]
        return SetupPacket(packet_type, expiration_time, sphinx_packet,
                           fs_payload, max_hops=max_hops)

    def pack(self):
        """
        Return the packet as a byte sequence

        :returns: raw packet (byte sequence)
        :rtype: bytes
        """
        return (HornetPacketType.to_bytes(self.packet_type) +
                self.max_hops.to_bytes(MAX_HOPS_LENGTH, "big") +
                self.expiration_time.to_bytes(TIMESTAMP_LENGTH, "big") +
                self.sphinx_packet.pack() + self.fs_payload)

    def get_type(self):
        """
        Return the type of the packet

        :rtype: :class:`HornetPacketType`
        """
        return self.packet_type

    def get_first_hop(self):
        """
        Return the first hop to which the packet should be forwarded,
        or None if it is not specified

        :rtype: bytes or NoneType
        """
        return self.first_hop


class AnonymousHeader(object):
    """
    Header for a Hornet data packet

    :ivar packet_type: Type of the packet must be one of the
        :class:`HornetPacketType`.SETUP_TYPES types
    :vartype packet_type: int
    :ivar nonce: Nonce needed for the onion encryption/decryption
        of the payload
    :vartype nonce: bytes
    :ivar current_fs: The current (i.e. for the receiving node) forwarding
        segment.
    :vartype current_fs: bytes
    :ivar current_mac: The current (i.e. for the receiving node) Message
        Authentication Code (MAC)
    :vartype current_mac: bytes
    :ivar blinded_aheader: The blinded anonymous header (containing the FSes
        and MACs for the following hops).
    :vartype blinded_aheader: bytes
    :ivar first_hop: Address (routing information) of the first hop to which
        the packet should be sent to.
    :ivar first_hop: bytes
    """

    def __init__(self, packet_type, nonce, current_fs, current_mac,
                 blinded_aheader, first_hop=None, max_hops=DEFAULT_MAX_HOPS):
        assert isinstance(packet_type, int)
        assert isinstance(nonce, bytes)
        assert len(nonce) == NONCE_LENGTH
        assert isinstance(current_fs, bytes)
        assert len(current_fs) == FS_LENGTH
        assert isinstance(current_mac, bytes)
        assert len(current_mac) == MAC_SIZE
        assert isinstance(blinded_aheader, bytes)
        assert first_hop is None or isinstance(first_hop, bytes)
        assert isinstance(max_hops, int)
        assert len(blinded_aheader) == compute_blinded_aheader_size(max_hops)
        if packet_type not in HornetPacketType.DATA_TYPES:
            raise TypeError("expected setup type, one of " +
                            str(HornetPacketType.SETUP_TYPES))
        self.packet_type = packet_type
        self.max_hops = max_hops
        self.nonce = nonce
        self.current_fs = current_fs
        self.current_mac = current_mac
        self.blinded_aheader = blinded_aheader
        self.first_hop = first_hop

    @classmethod
    def parse_bytes_to_header(cls, raw):
        """
        Parses the raw data and creates an :class:`AnonymousHeader`

        :returns: the newly-created AnonymousHeader instance
        :rtype: :class:`AnonymousHeader`
        """
        assert isinstance(raw, bytes)
        max_hops_index = HornetPacketType.length()
        nonce_index = max_hops_index + MAX_HOPS_LENGTH
        current_fs_index = nonce_index + NONCE_LENGTH
        current_mac_index = current_fs_index + FS_LENGTH
        blinded_aheader_index = current_mac_index + MAC_SIZE

        packet_type = HornetPacketType.from_bytes(raw[:max_hops_index])
        max_hops = int.from_bytes(raw[max_hops_index:nonce_index], "big")
        nonce = raw[nonce_index:current_fs_index]
        current_fs = raw[current_fs_index:current_mac_index]
        current_mac = raw[current_mac_index:blinded_aheader_index]
        blinded_aheader = raw[blinded_aheader_index:]
        return AnonymousHeader(packet_type, nonce, current_fs, current_mac,
                               blinded_aheader, max_hops=max_hops)

    def pack(self):
        """
        Return the header as a byte sequence

        :returns: raw header (byte sequence)
        :rtype: bytes
        """
        return (HornetPacketType.to_bytes(self.packet_type) +
                self.max_hops.to_bytes(MAX_HOPS_LENGTH, "big") +
                self.nonce + self.current_fs + self.current_mac +
                self.blinded_aheader)


class DataPacket(HornetPacket):
    """
    Hornet data packet, composed of an AnonymousHeader and a payload.

    :ivar header: the header of the DataPacket
    :vartype header: :class:`AnonymousHeader`
    :ivar payload: the data payload of the DataPacket
    :vartype payload: bytes
    """

    def __init__(self, header, payload):
        assert isinstance(header, AnonymousHeader)
        assert isinstance(payload, bytes)
        self.header = header
        self.payload = payload

    @classmethod
    def parse_bytes_to_packet(cls, raw):
        """
        Parses the raw data and creates a DataPacket.

        :returns: the newly-created DataPacket instance
        :rtype: :class:`DataPacket`
        """
        assert isinstance(raw, bytes)
        raw_header = raw[:-DATA_PAYLOAD_LENGTH]
        header = AnonymousHeader.parse_bytes_to_header(raw_header)
        payload = raw[-DATA_PAYLOAD_LENGTH:]
        return DataPacket(header, payload)

    def pack(self):
        """
        Return the packet as a byte sequence

        :returns: raw packet (byte sequence)
        :rtype: bytes
        """
        return self.header.pack() + self.payload

    def get_type(self):
        """
        Return the type of the packet

        :rtype: :class:`HornetPacketType`
        """
        return self.header.packet_type

    def get_first_hop(self):
        """
        Return the first hop to which the packet should be forwarded,
        or None if it is not specified

        :rtype: bytes or NoneType
        """
        return self.header.first_hop


def test_setup(max_hops=DEFAULT_MAX_HOPS):
    dh_pubkey_0 = b'1'*GROUP_ELEM_LENGTH
    mac_0 = b'2'*MAC_SIZE
    blinded_header = b'3'*sphinx_packet_mod.compute_blinded_header_size(
                                                max_hops=max_hops)
    first_hop = b'4'*DEFAULT_ADDRESS_LENGTH
    sphinx_payload = b'5'*sphinx_packet_mod.DEFAULT_PAYLOAD_LENGTH
    sphinx_header = SphinxHeader(dh_pubkey_0, mac_0, blinded_header, first_hop)
    sphinx_packet = SphinxPacket(sphinx_header, sphinx_payload)

    packet_type = HornetPacketType.SETUP_FWD
    expiration_time = 1426520000
    fs_payload = b'6'*compute_fs_payload_size(max_hops=max_hops)
    setup_packet = SetupPacket(packet_type, expiration_time, sphinx_packet,
                               fs_payload, max_hops=max_hops)
    raw_packet = setup_packet.pack()

    parsed_packet = SetupPacket.parse_bytes_to_packet(raw_packet)
    assert parsed_packet.packet_type == packet_type
    assert parsed_packet.expiration_time == expiration_time
    assert parsed_packet.sphinx_packet.pack() == sphinx_packet.pack()
    assert parsed_packet.fs_payload == fs_payload


def test_data_transmission(max_hops=DEFAULT_MAX_HOPS):
    packet_type = HornetPacketType.DATA_FWD
    nonce = b'1'*NONCE_LENGTH
    current_fs = b'2'*FS_LENGTH
    current_mac = b'3'*MAC_SIZE
    blinded_aheader = b'4'*compute_blinded_aheader_size(max_hops)
    header = AnonymousHeader(packet_type, nonce, current_fs, current_mac,
                             blinded_aheader, max_hops=max_hops)
    payload = b'5'*DATA_PAYLOAD_LENGTH
    data_packet = DataPacket(header, payload)
    raw_packet = data_packet.pack()

    parsed_packet = DataPacket.parse_bytes_to_packet(raw_packet)
    assert parsed_packet.header.packet_type == packet_type
    assert parsed_packet.header.max_hops == max_hops
    assert parsed_packet.header.nonce == nonce
    assert parsed_packet.header.current_fs == current_fs
    assert parsed_packet.header.current_mac == current_mac
    assert parsed_packet.header.blinded_aheader == blinded_aheader
    assert parsed_packet.payload == payload


if __name__ == "__main__":
    test_setup()
    test_setup(max_hops=15)
    test_setup(max_hops=5)
    test_data_transmission()
    test_data_transmission(max_hops=15)
    test_data_transmission(max_hops=5)

