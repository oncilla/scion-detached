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
from curve25519.keys import Private
from lib.privacy.session import SetupPathData, SessionRequestInfo
from lib.privacy.hornet_packet import compute_fs_payload_size, SetupPacket,\
    HornetPacketType
from lib.privacy.hornet_crypto_util import generate_initial_fs_payload
import os
import time


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
        payload = bwd_header.pack()
        sphinx_packet = (self._sphinx_end_host.
                        construct_forward_packet(payload,
                                                 fwd_shared_sphinx_keys,
                                                 fwd_header))
        setup_packet = SetupPacket(HornetPacketType.SETUP_FWD,
                                   session_expiration_time, sphinx_packet,
                                   fwd_initial_fs_payload,
                                   self._sphinx_end_host.max_hops)
        return (session_id, setup_packet)


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
    node_1.process_incoming_packet(raw_packet)


if __name__ == "__main__":
    test()
