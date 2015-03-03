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
:mod:`sphinx_node` --- Sphinx node
==================================

This module defines the Sphinx node, main processing unit of the Sphinx protocol.

"""

class ProcessingResult(object):
    """
    Result of the processing of a :class:`SphinxPacket`

    :ivar type: the type of the result
    :vartype type: :class:`ProcessingResult.ResultType`
    :ivar result: the result of the processing. The format depends on the type:
        - if the type is FORWARD, it is (next_hop, packet);
        - if the type is AT_DESTINATION, it is (payload_message);
        - if the type is DROP, it is None or (error_message).
    :vartype result: tuple
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
    A destination of such a packet is a SphinxNode as well.

    :ivar public_key: public key of the SphinxNode
    :vartype public_key: bytes
    :ivar private_key: private key of the SphinxNode
    :vartype private_key: bytes
    """

    def __init__(self, public_key, private_key, name=None):
        self.public_key = public_key
        self.private_key = private_key
        self.name = name

    def process_packet(self, packet):
        """
        Process a Sphinx packet
        """
        pass

