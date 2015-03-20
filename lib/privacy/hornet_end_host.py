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
from lib.privacy.sphinx.sphinx_end_host import SphinxEndHost,\
    compute_shared_keys
import uuid
from curve25519.keys import Private, Public
from lib.privacy.session import SetupPathData, SessionRequestInfo
from lib.privacy.hornet_packet import compute_fs_payload_size, SetupPacket,\
    HornetPacketType, SHARED_KEY_LENGTH
from lib.privacy.hornet_crypto_util import generate_initial_fs_payload
import os
import time
from lib.privacy.hornet_processing import HornetProcessingResult
from lib.privacy.common.exception import PacketParsingException
from lib.privacy.sphinx.packet import SphinxHeader
from lib.privacy.common.constants import LOCALHOST_ADDRESS,\
    DEFAULT_ADDRESS_LENGTH
import itertools


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
        self._session_requests_by_reply_id = dict()
        self._session_requests_by_session_id = dict()
        self._open_sessions = dict()

    def add_session_request_info(self, session_request_info):
        """
        Store a :class:`session.SessionRequestInfo` instance for a new session
        request.
        """
        assert isinstance(session_request_info, SessionRequestInfo)
        self._session_requests_by_session_id[session_request_info.session_id]\
            = session_request_info
        self._session_requests_by_reply_id[session_request_info.reply_id]\
            = session_request_info

    def remove_session_request_info(self, session_id=None, reply_id=None):
        """
        Store a :class:`session.SessionRequestInfo` instance for a new session
        request.
        """
        assert [session_id, reply_id].count(None) == 1
        if session_id in self._session_requests_by_session_id:
            reply_id = (self._session_requests_by_session_id[session_id]
                        .reply_id)
        elif reply_id in self._session_requests_by_reply_id:
            session_id = (self._session_requests_by_reply_id[reply_id]
                        .session_id)
        else:
            return # session_id already deleted
        del self._session_requests_by_session_id[session_id]
        del self._session_requests_by_reply_id[reply_id]

    def create_new_session_request(self, fwd_path, fwd_pubkeys, bwd_path,
                                   bwd_pubkeys, session_expiration_time,
                                   valid_for_seconds = None):
        """
        Construct the first packet of the setup, and store information about
        the session request, returning a request_id referring to it.

        :returns: a tuple containing a new session identifier and the first
            packet that needs to be sent out: (session_id, first_packet)
        """
        assert len(fwd_path) == len(fwd_pubkeys)
        assert len(bwd_path) == len(bwd_pubkeys)
        for address in itertools.chain(fwd_path, bwd_path):
            assert isinstance(address, bytes)
            assert len(address) == DEFAULT_ADDRESS_LENGTH
        # pylint: disable=no-member
        session_id = uuid.uuid4().int
        # pylint: enable=no-member
        fs_payload_length = compute_fs_payload_size(self._sphinx_end_host.
                                                    max_hops)

        #FIXME:Daniele: Add MAC extension for sphinx headers so that
        #   the per-hop MACs cover also Hornet's expiration time (EXP)
        # Construct SphinxHeader and SetupPathData for forward path
        source_tmp_private = Private()
        source_tmp_pubkey = source_tmp_private.get_public().serialize()
        fwd_shared_sphinx_keys, blinding_factors, _ = \
            compute_shared_keys(source_tmp_private, fwd_pubkeys)
        fwd_header = (self._sphinx_end_host.
                      construct_header(fwd_shared_sphinx_keys,
                                       source_tmp_pubkey, fwd_path))
        fwd_initial_fs_payload = os.urandom(fs_payload_length)
        fwd_path_data = SetupPathData(source_tmp_private, blinding_factors,
                                      fwd_shared_sphinx_keys, fwd_path,
                                      fwd_initial_fs_payload)
        dest_shared_key = fwd_shared_sphinx_keys[-1]

        # Construct SphinxHeader and SetupPathData for backward path
        source_tmp_private = Private()
        source_tmp_pubkey = source_tmp_private.get_public().serialize()
        bwd_shared_sphinx_keys, blinding_factors, final_dh_pubkey = \
            compute_shared_keys(source_tmp_private, bwd_pubkeys)
        bwd_header = (self._sphinx_end_host.
                      construct_header(bwd_shared_sphinx_keys,
                                       source_tmp_pubkey, bwd_path))
        bwd_initial_fs_payload = generate_initial_fs_payload(dest_shared_key,
                                                             fs_payload_length)
        bwd_path_data = SetupPathData(source_tmp_private, blinding_factors,
                                      bwd_shared_sphinx_keys, bwd_path,
                                      bwd_initial_fs_payload)
        self._sphinx_end_host.add_expected_reply(final_dh_pubkey,
                                                 bwd_shared_sphinx_keys,
                                                 dest_shared_key)

        # Construct new SessionRequestInfo object and store it
        reply_id = final_dh_pubkey
        session_request_info = SessionRequestInfo(session_id, fwd_path_data,
                                                  bwd_path_data, reply_id,
                                                  valid_for_seconds)
        self.add_session_request_info(session_request_info)

        # Construct the first setup packet
        #FIXME:Daniele: add end-to-end MAC?
        payload = bwd_path[0] + bwd_header.pack()
        sphinx_packet = (self._sphinx_end_host.
                        construct_forward_packet(payload,
                                                 fwd_shared_sphinx_keys,
                                                 fwd_header))
        setup_packet = SetupPacket(HornetPacketType.SETUP_FWD,
                                   session_expiration_time, sphinx_packet,
                                   fwd_initial_fs_payload,
                                   first_hop=fwd_path[0],
                                   max_hops=self._sphinx_end_host.max_hops)
        return (session_id, setup_packet)


class HornetDestination(HornetNode):
    """
    A Hornet destination.

    :ivar secret_key: secret key of the HornetNode (SV in the paper)
    :vartype secret_key: bytes
    :ivar private: private key of the HornetNode
    :vartype private: bytes or :class:`curve25519.keys.Private`
    :ivar public: public key of the HornetNode
    :vartype public: bytes
    """

    def __init__(self, secret_key, private, public=None):
        assert isinstance(secret_key, bytes)
        super().__init__(secret_key, private=private)
        self._open_sessions = dict()

    def process_setup_packet(self, raw_packet):
        """
        Process an incoming Hornet setup packet
        (:class:`hornet_packet.SetupPacket`), and return an instance of class
        :class:`hornet_processing.HornetProcessingResult`.
        """
        try:
            packet = SetupPacket.parse_bytes_to_packet(raw_packet)
        except PacketParsingException:
            return HornetProcessingResult(HornetProcessingResult.Type.INVALID)
        if packet.expiration_time <= int(time.time()):
            return HornetProcessingResult(HornetProcessingResult.Type.INVALID)
        # Process the sphinx packet
        sphinx_packet = packet.sphinx_packet
        try:
            sphinx_processing_result = \
                self._sphinx_node.get_packet_processing_result(sphinx_packet)
        except:
            return HornetProcessingResult(HornetProcessingResult.Type.INVALID)
        if not sphinx_processing_result.is_at_destination():
            return HornetProcessingResult(HornetProcessingResult.Type.INVALID)
        payload = sphinx_processing_result.result
        first_hop = payload[:DEFAULT_ADDRESS_LENGTH]
        raw_header = payload[DEFAULT_ADDRESS_LENGTH:]
        bwd_sphinx_header = SphinxHeader.parse_bytes_to_header(raw_header)
        # Create new shared_key (forward secrecy) from a new Private
        tmp_private = Private()
        source_public = Public(sphinx_processing_result.source_pubkey)
        long_shared_key = tmp_private.get_shared_key(source_public)
        shared_key = long_shared_key[:SHARED_KEY_LENGTH]
        # Add a new FS to the FS payload
        #TODO:Daniele: something more useful than the localhost address could
        #   be stored in the FS of the destination
        new_fs = self.create_forwarding_segment(shared_key, LOCALHOST_ADDRESS,
                                                packet.expiration_time)
        tmp_pubkey = tmp_private.get_public().serialize()
        sphinx_shared_key = sphinx_processing_result.shared_key
        processed_fs_payload = self.add_fs_to_fs_payload(sphinx_shared_key,
                                                         new_fs,
                                                         tmp_pubkey,
                                                         packet.fs_payload)
        # Generate the new FS payload
        fs_payload_length = compute_fs_payload_size(self._sphinx_node.max_hops)
        new_fs_payload = generate_initial_fs_payload(sphinx_shared_key,
                                                     fs_payload_length)
        # Generate the new Sphinx packet
        sphinx_reply_packet = (self._sphinx_node.
                               construct_reply_packet(processed_fs_payload,
                                                      sphinx_shared_key,
                                                      bwd_sphinx_header))
        # Create the second setup packet to send back to the source
        second_packet = SetupPacket(packet.packet_type,
                                    packet.expiration_time,
                                    sphinx_reply_packet,
                                    new_fs_payload,
                                    first_hop=first_hop,
                                    max_hops=packet.max_hops)
        return HornetProcessingResult(HornetProcessingResult
                                      .Type.SESSION_REQUEST,
                                      packet_to_send=second_packet)


def test():
    private = Private()
    secret_key = b'1'*32
    source = HornetSource(secret_key, private)

    fwd_path = [b'1'*16, b'2'*16, b'3'*16]
    bwd_path = [b'2'*16, b'1'*16, b'source_address00']
    node_1_private = Private()
    node_2_private = Private()
    node_3_private = Private()
    fwd_privates = [node_1_private, node_2_private, node_3_private]
    fwd_pubkeys = [p.get_public() for p in fwd_privates]
    bwd_pubkeys = fwd_pubkeys[-2::-1]
    bwd_pubkeys.append(source.public)
    session_expiration_time = int(time.time()) + 60
    sid, packet = source.create_new_session_request(fwd_path, fwd_pubkeys,
                                                    bwd_path, bwd_pubkeys,
                                                    session_expiration_time)
    raw_packet = packet.pack()

    secret_key = b'2'*32
    node_1 = HornetNode(secret_key, node_1_private)
    result = node_1.process_incoming_packet(raw_packet)
    assert result.result_type == HornetProcessingResult.Type.FORWARD


if __name__ == "__main__":
    test()
