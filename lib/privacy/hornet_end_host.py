"""
:mod:`hornet_end_host` --- HORNET end host
==========================================

This module defines the HORNET end hosts, both the source,
:class:`HornetSource`, and the destination, :class:`HornetDestination`.

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
from lib.privacy.hornet_node import HornetNode
from lib.privacy.sphinx.sphinx_end_host import SphinxEndHost


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
        :ivar INVALID: the packet is not valid, no action is required
        """
        RECEIVED_DATA = 0
        SESSION_REQUEST = 1
        SESSION_ESTABLISHED = 2
        SESSION_EXPIRED = 3
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


class HornetSource(HornetNode):
    """
    A Hornet source, able to establish a session and to exchange data packets
    (:class:`hornet_packet.DataPacket`).

    :ivar secret_key: secret key of the HornetNode (SV in the paper)
    :vartype secret_key: bytes
    :ivar private: private key of the HornetNode
    :vartype private: bytes or :class:`curve25519.keys.Private`
    :ivar public: public key of the HornetNode
    :vartype public: bytes
    """

    def __init__(self, secret_key, private, public=None):
        assert isinstance(secret_key, bytes)
        self._sphinx_end_host = SphinxEndHost(private, public)
        super().__init__(secret_key, sphinx_node=self._sphinx_end_host)
        self._incomplete_sessions = dict()
        self._open_sessions = dict()

    def create_new_session_request(self, fwd_path, fwd_pubkeys, bwd_path,
                                   bwd_pubkeys):
        """
        Construct the first packet of the setup, and store in information about
        the session request, returning a request_id referring to it.
        """

