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


DEFAULT_MAX_HOPS = 8
DEFAULT_ADDRESS_LENGTH = 16
DEFAULT_GROUP_ELEM_LENGTH = 32


class SphinxHeader(object):
    """
    Header for a Sphinx packet
    """

    def __init__(self, dh_keyhalf_0, mac_0, blinded_header):
        """
        Create a new SphinxHeader.

        :param dh_keyhalf_0: Diffie-Hellman key-half for the first node
        :type dh_keyhalf_0: bytes
        :param mac_0: MAC for the first node
        :type mac_0: bytes
        :param blinded_header: Blinded header containing next hops and MACs
        :type blinded_header: bytes
        :returns: the newly-created SphinxHeader instance
        :rtype: SphinxHeader
        """
        self.dh_keyhalf_0 = dh_keyhalf_0
        self.mac_0 = mac_0
        self.blinded_header = blinded_header

    @classmethod
    def create_header(cls, dh_keyhalf_0, shared_keys=None, next_hops=None):
        """
        Create a new SphinxHeader

        :param dh_keyhalf_0: Diffie-Hellman key-half for the first node
        :type dh_keyhalf_0: bytes
        :param shared_keys: List of shared keys with all the nodes on the path
        :type shared_keys: list
        :param next_hops: list of node names (addresses) on the path
        :type next_hops: list
        :returns: the newly-created SphinxHeader instance
        :rtype: SphinxHeader
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
        :param address_length: length of a node address (name)
        :type max_hops: int
        :param group_elem_length: length of a group element (for Diffie-Hellman)
        :type max_hops: int
        :returns: the newly-created SphinxHeader instance
        :rtype: SphinxHeader
        """
        assert isinstance(raw, bytes)
        dh_keyhalf_0 = raw[0:group_elem_length]
        mac_0 = raw[group_elem_length:group_elem_length+16]
        blinded_header = raw[group_elem_length+16:
                             group_elem_length+16+address_length*max_hops]
        return SphinxHeader(dh_keyhalf_0, mac_0, blinded_header)

    def pack(self):
        """
        Return the header as a byte sequence

        :returns: raw header (byte sequence)
        :rtype: bytes
        """
        return self.dh_keyhalf_0 + self.mac_0 + self.blinded_header

