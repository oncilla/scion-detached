"""
:mod:`hornet_processing_interfact` --- HORNET processing interface
==================================================================

This module defines the class :class:`HornetProcessingResult`, which is used
to return the result of packet processing by :class:`HornetNode`,
:class:`HornetSource` and :class:`HornetDestination:

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


class HornetProcessingResult(object):
    """
    Result of the processing of a Hornet packet.

    :ivar result_type: The type of the processing result
    :vartype result_type: int (see :class:`HornetProcessingResult.Type`)
    :ivar session_id: identifier of the session to which the packet belongs,
        if applicable (else None)
    :ivar received_data: Data received (from a data packet)
    :vartype received_data: bytes
    :vartype session_id: int
    :ivar packet_to_send: Raw packet that needs to be sent, if any (else None)
    :vartype packet_to_send: bytes
    """

    class Type(object):
        """
        Type of the result of the processing of a Hornet Packet

        :ivar RECEIVED_DATA: the packet carried used data
        :ivar SESSION_REQUEST: the processed packet is a valid setup request,
            which requires the second setup packet to be sent back.
        :ivar SESSION_ESTABLISHED: a new session was established (as a source,
            this requires the sending of the last setup packet which will
            provide the destination with the backward AnonymousHeader
        :ivar SESSION_EXPIRED: the packet corresponds to an expired session
        :ivar FORWARD: the packet was processed and needs to be forwarded
        :ivar INVALID: the packet is not valid, no action is required
        """
        RECEIVED_DATA = 0
        SESSION_REQUEST = 1
        SESSION_ESTABLISHED = 2
        SESSION_EXPIRED = 3
        FORWARD = 8
        INVALID = 100

        ALL_TYPES = (RECEIVED_DATA, SESSION_REQUEST, SESSION_ESTABLISHED,
                     SESSION_EXPIRED, INVALID)

    def __init__(self, result_type, session_id=None, received_data=None,
                 packet_to_send=None):
        assert result_type in HornetProcessingResult.Type.ALL_TYPES
        assert session_id is None or isinstance(session_id, int)
        assert received_data is None or isinstance(received_data, bytes)
        assert packet_to_send is None or isinstance(packet_to_send, bytes)
        self.result_type = result_type
        self.session_id = session_id
        self.received_data = received_data
        self.packet_to_send = packet_to_send

