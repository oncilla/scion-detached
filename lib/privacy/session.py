"""
:mod:`session` --- HORNET session data structures
=================================================

This module defines the data structures used by HORNET to keep track of
sessions and session requests.

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
from curve25519.keys import Private
import time
from lib.privacy.hornet_packet import AnonymousHeader, FS_LENGTH,\
    SHARED_KEY_LENGTH, compute_blinded_aheader_size
from lib.privacy.common.constants import MAC_SIZE


# Min, max and default lifetime of a session request in seconds
MIN_SESSION_REQUEST_DURATION_SEC = 2
MAX_SESSION_REQUEST_DURATION_SEC = 60
DEFAULT_SESSION_REQUEST_DURATION_SEC = 10
# Default lifetime of a session in seconds
DEFAULT_SESSION_DURATION_SEC = 3600  # 3600 = 1 Hour


class SetupPathData(object):
    """
    Data structure containing information related to a path (forward or
    backward) for a session establishment attempt.

    :ivar source_private: First temporary private key of the source
        (the one for the first hop node)
    :vartype source_private: :class:`curve25519.key.Private`
    :ivar blinding_factors: Blinding factors to compute the temporary private
        keys of the source for the hops following the first.
    :ivar blinding_factors: list
    :ivar shared_sphinx_keys: Shared keys for the Sphinx setup
    :vartype shared_sphinx_keys: list
    :ivar path: List of nodes (addresses/routing info) on the path, where the
        first is the address of the first-hop node, needed by the sender of the
        first packet on the path (source, in case of a forward path,
        destination in case of a backward path)
    :vartype path: list
    :ivar initial_fs_payload: Initial value of the fs_payload
    :vartype initial_fs_payload: bytes
    """

    def __init__(self, source_private, blinding_factors, shared_sphinx_keys,
                 path, initial_fs_payload):
        assert (isinstance(source_private, bytes) or
                isinstance(source_private, Private))
        for blinding_factor in blinding_factors:
            assert isinstance(blinding_factor, Private)
        for shared_key in shared_sphinx_keys:
            assert isinstance(shared_key, bytes)
        assert isinstance(initial_fs_payload, bytes)
        assert len(blinding_factors) == len(shared_sphinx_keys) - 1
        assert len(shared_sphinx_keys) == len(path)
        self.source_private = source_private
        self.blinding_factors = blinding_factors
        self.shared_sphinx_keys = shared_sphinx_keys
        self.path = path
        self.initial_fs_payload = initial_fs_payload


class TransmissionPathData(object):
    """
    Data structure containing information related to a path (forward or
    backward) for an established session.

    :ivar anonymous_header: Anonymous header for the path
    :vartype anonymous_header: :class:`hornet_packet.AnonymousHeader`
    :ivar shared_keys: Shared keys established with each node on the path
    :vartype shared_keys: list
    :ivar path: List of nodes (addresses/routing info) on the path, where the
        first is the address of the first-hop node, needed by the sender of the
        first packet on the path (source, in case of a forward path,
        destination in case of a backward path)
    :vartype path: list
    """

    def __init__(self, anonymous_header, shared_keys, path):
        assert isinstance(anonymous_header, AnonymousHeader)
        for shared_key in shared_keys:
            assert isinstance(shared_key, bytes)
        assert len(shared_keys) == len(path)
        self.anonymous_header = anonymous_header
        self.shared_keys = shared_keys
        self.path = path


class SessionRequestInfo(object):
    """
    Information relating to an incomplete session establishment attempt.

    :ivar session_id: Identifier of the session (for the caller); once the
        session is set up, the same id will be used for the open session.
    :vartype session_id: int
    :ivar forward_path_data: Data about the forward path
    :vartype forward_path_data: :class:`SetupPathData`
    :ivar backward_path_data: Data about the backward path
    :vartype backward_path_data: :class:`SetupPathData`
    :ivar reply_id: identifier for the sphinx reply
    :vartype reply_id: bytes or int or string
    :ivar time_created: timestamp indicating the time when the request was
        created
    :vartype time_created: int
    :ivar expiration_time: timestamp indicating the time after which the
        request will be considered to be expired.
    :vartype expiration_time: int
    """

    def __init__(self, session_id, forward_path_data, backward_path_data,
                 reply_id, valid_for_seconds=None):
        assert isinstance(session_id, int)
        assert isinstance(forward_path_data, SetupPathData)
        assert isinstance(backward_path_data, SetupPathData)
        if valid_for_seconds is not None:
            assert isinstance(valid_for_seconds, int)
            if not (MIN_SESSION_REQUEST_DURATION_SEC <= valid_for_seconds <=
                    MAX_SESSION_REQUEST_DURATION_SEC):
                raise ValueError("session request lifetime must be between" +
                                 str(MIN_SESSION_REQUEST_DURATION_SEC) +
                                 " and " +
                                 str(MAX_SESSION_REQUEST_DURATION_SEC))
        else:
            valid_for_seconds = DEFAULT_SESSION_REQUEST_DURATION_SEC
        self.session_id = session_id
        self.forward_path_data = forward_path_data
        self.backward_path_data = backward_path_data
        self.reply_id = reply_id
        self.time_created = int(time.time())
        self.expiration_time = self.time_created + valid_for_seconds


class SessionInfo(object):
    """
    Information relating to an established session. This is a base class
    to be used by any :class:`hornet_end_host.HornetEndHost`, i.e. both
    source and destination.

    :ivar session_id: Identifier of the session (for the caller).
    :vartype session_id: int
    :ivar incoming_forwarding_segment: forwarding segment of the end host,
        part of the forward :class:`hornet_packet.AnonymousHeader` that allows
        the end host to match an incoming data packet to an open session.
    :vartype incoming_forwarding_segment: bytes
    :ivar incoming_mac: mac of the incoming packet, used together with the
        incoming_forwarding_segment and the incoming_blinded_header to quickly
        verify the integrity of the header of an incoming data packet by simply
        checking for the equality of the values to those verified at the
        receipt of the first data packet (when the session is created).
    :vartype incoming_mac: bytes
    :ivar incoming_blinded_header: blinded_header of the incoming packet, used
        together with the incoming_forwarding_segment and the incoming_mac to
        quickly verify the integrity of the header of an incoming data packet
        by simply checking for the equality of the values to those verified at
        the receipt of the first data packet (when the session is created).
    :vartype incoming_blinded_header: bytes
    :ivar time_created: timestamp indicating the time when the session was
        established
    :vartype time_created: int
    :ivar expiration_time: timestamp indicating the time after which the
        session will be considered to be expired.
    :vartype expiration_time: int
    """

    def __init__(self, session_id, incoming_forwarding_segment, incoming_mac,
                 incoming_blinded_aheader, expiration_time):
        assert isinstance(session_id, int)
        assert isinstance(expiration_time, int)
        assert isinstance(incoming_forwarding_segment, bytes)
        assert len(incoming_forwarding_segment) == FS_LENGTH
        assert isinstance(incoming_mac, bytes)
        assert len(incoming_mac) == MAC_SIZE
        assert isinstance(incoming_blinded_aheader, bytes)
        self.session_id = session_id
        self.forwarding_segment = incoming_forwarding_segment
        self.incoming_mac = incoming_mac
        self.incoming_blinded_aheader = incoming_blinded_aheader
        self.time_created = int(time.time())
        self.expiration_time = expiration_time

class SourceSessionInfo(SessionInfo):
    """
    Information relating to an established session.

    :ivar session_id: Identifier of the session (for the caller).
    :vartype session_id: int
    :ivar forward_path_data: Data about the forward path
    :vartype forward_path_data: :class:`TransmissionPathData`
    :ivar backward_path_data: Data about the backward path
    :vartype backward_path_data: :class:`TransmissionPathData`
    :ivar incoming_forwarding_segment: dummy forwarding segment of the source,
        part of the backward :class:`hornet_packet.AnonymousHeader` that allows
        the source to match an incoming data packet to an open session.
    :vartype incoming_forwarding_segment: bytes
    :ivar incoming_mac: mac of the incoming packet, used together with the
        incoming_forwarding_segment and the incoming_blinded_header to quickly
        verify the integrity of the header of an incoming data packet by simply
        checking for the equality of the values to those verified at the
        receipt of the first data packet (when the session is created).
    :vartype incoming_mac: bytes
    :ivar incoming_blinded_header: blinded_header of the incoming packet, used
        together with the incoming_forwarding_segment and the incoming_mac to
        quickly verify the integrity of the header of an incoming data packet
        by simply checking for the equality of the values to those verified at
        the receipt of the first data packet (when the session is created).
    :vartype incoming_blinded_header: bytes
    :ivar time_created: timestamp indicating the time when the session was
        established
    :vartype time_created: int
    :ivar expiration_time: timestamp indicating the time after which the
        session will be considered to be expired.
    :vartype expiration_time: int
    """

    def __init__(self, session_id, forward_path_data, backward_path_data,
                 incoming_forwarding_segment, incoming_mac,
                 incoming_blinded_aheader, valid_for_seconds=None):
        assert isinstance(forward_path_data, TransmissionPathData)
        assert isinstance(backward_path_data, TransmissionPathData)
        assert isinstance(incoming_forwarding_segment, bytes)
        assert len(incoming_forwarding_segment) == FS_LENGTH
        if valid_for_seconds is not None:
            assert isinstance(valid_for_seconds, int)
            if valid_for_seconds < 0:
                raise ValueError("session lifetime must be positive")
        else:
            valid_for_seconds = DEFAULT_SESSION_DURATION_SEC
        SessionInfo.__init__(self, session_id, incoming_forwarding_segment,
                             incoming_mac, incoming_blinded_aheader,
                             int(time.time()) + valid_for_seconds)
        self.forward_path_data = forward_path_data
        self.backward_path_data = backward_path_data


class DestinationSessionInfo(SessionInfo):
    """
    Information relating to an established session on the destination.

    :ivar session_id: Identifier of the session (for the caller).
    :vartype session_id: int
    :ivar shared_key: key shared with the source.
    :vartype shared_key: bytes
    :ivar incoming_forwarding_segment: forwarding segment of the destination,
        part of the forward :class:`hornet_packet.AnonymousHeader` that allows
        the destination to match an incoming data packet to an open session.
    :vartype incoming_forwarding_segment: bytes
    :ivar incoming_mac: mac of the incoming packet, used together with the
        incoming_forwarding_segment and the incoming_blinded_header to quickly
        verify the integrity of the header of an incoming data packet by simply
        checking for the equality of the values to those verified at the
        receipt of the first data packet (when the session is created).
    :vartype incoming_mac: bytes
    :ivar incoming_blinded_header: blinded_header of the incoming packet, used
        together with the incoming_forwarding_segment and the incoming_mac to
        quickly verify the integrity of the header of an incoming data packet
        by simply checking for the equality of the values to those verified at
        the receipt of the first data packet (when the session is created).
    :vartype incoming_blinded_header: bytes
    :ivar backward_anonymous_header: Anonymous header for the backward path
        (from the destination to the source)
    :vartype backward_anonymous_header: :class:`hornet_packet.AnonymousHeader`
    :ivar time_created: timestamp indicating the time when the session was
        established
    :vartype time_created: int
    :ivar expiration_time: timestamp indicating the time after which the
        session will be considered to be expired.
    :vartype expiration_time: int
    """

    def __init__(self, session_id, shared_key, incoming_forwarding_segment,
                 incoming_mac, incoming_blinded_aheader,
                 backward_anonymous_header, expiration_time):
        assert isinstance(shared_key, bytes)
        assert len(shared_key) == SHARED_KEY_LENGTH
        assert isinstance(backward_anonymous_header, AnonymousHeader)
        SessionInfo.__init__(self, session_id, incoming_forwarding_segment,
                             incoming_mac, incoming_blinded_aheader,
                             expiration_time)
        self.shared_key = shared_key
        self.backward_anonymous_header = backward_anonymous_header

