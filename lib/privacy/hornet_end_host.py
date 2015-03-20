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
    HornetPacketType, SHARED_KEY_LENGTH, FS_LENGTH, compute_blinded_aheader_size
from lib.privacy.hornet_crypto_util import generate_initial_fs_payload,\
    derive_fs_payload_stream_key, derive_fs_payload_mac_key,\
    derive_aheader_stream_key
import os
import time
from lib.privacy.hornet_processing import HornetProcessingResult
from lib.privacy.common.exception import PacketParsingException
from lib.privacy.sphinx.packet import SphinxHeader, SphinxPacket
from lib.privacy.common.constants import LOCALHOST_ADDRESS,\
    DEFAULT_ADDRESS_LENGTH, GROUP_ELEM_LENGTH, MAC_SIZE
import itertools
from lib.privacy.sphinx.sphinx_crypto_util import stream_cipher_encrypt,\
    verify_mac, stream_cipher_decrypt


class _MacVerificationFailure(Exception):
    """
    Exception indicating the failed verification of a Message Authentication
    Code (MAC).
    """
    pass


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
        reply_id = final_dh_pubkey.serialize()
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

    @staticmethod
    def construct_anonymous_header(shared_keys):
        """
        Construct an anonymous header (:class:`hornet_packet.AnonymousHeader`).
        """
        pad_size = FS_LENGTH + MAC_SIZE
        blinded_header_size = compute_blinded_aheader_size()
        aheader_size = pad_size + blinded_header_size
        number_of_hops = len(shared_keys)
        stream_keys = [derive_aheader_stream_key(shared_key)
                       for shared_key in shared_keys]

        # Create filler string
        long_filler = b'\0' * aheader_size
        for stream_key in stream_keys[:-1]:
            long_filler = long_filler[pad_size:] + b'\0'*pad_size
            long_filler = stream_cipher_decrypt(stream_key, long_filler)
        filler_length = pad_size * number_of_hops
        filler = long_filler[-filler_length:]
        #FIXME:Daniele: Finish this method (change filler_length?)

    @staticmethod
    def _retrieve_fses_and_pubkeys(fs_payload, shared_sphinx_keys,
                                   initial_fs_payload):
        """
        Retrieves all the forwarding segments and the temporary public keys of
        the nodes in the fs_payload, using the keys and the initial forwarding
        segment provided. This function checks also all the MACs added by the
        nodes at each hop: if all check succeed, the list of retrieved
        forwarding segment is returned, else raise an exception.
        """
        stream_keys = [derive_fs_payload_stream_key(shared_key)
                       for shared_key in shared_sphinx_keys]
        mac_keys = [derive_fs_payload_mac_key(shared_key)
                       for shared_key in shared_sphinx_keys]
        # Compute the list of dropped padding by simulating the processing of
        # each node on the path
        fake_fs_and_pubkey = b'\0' * (FS_LENGTH + GROUP_ELEM_LENGTH)
        fake_mac = b'\0' * MAC_SIZE
        dropped_length = FS_LENGTH + GROUP_ELEM_LENGTH + MAC_SIZE
        tmp_payload = initial_fs_payload
        dropped_paddings = []
        for stream_key in stream_keys:
            dropped_paddings.append(tmp_payload[-dropped_length:])
            tmp_payload = fake_fs_and_pubkey + tmp_payload[:-dropped_length]
            tmp_payload = fake_mac + stream_cipher_encrypt(stream_key,
                                                          tmp_payload)
        # Retrieve the FSes and the temporary public keys by reverting the
        # steps done by each node (see
        # :func:`hornet_node.add_fs_to_fs_payload`)
        fs_list = []
        pubkey_list = []
        for stream_key, mac_key in zip(reversed(stream_keys),
                                       reversed(mac_keys)):
            mac = fs_payload[:MAC_SIZE]
            tmp_payload = fs_payload[MAC_SIZE:]
            if not verify_mac(mac_key, tmp_payload, mac):
                raise _MacVerificationFailure()
            tmp_payload = stream_cipher_decrypt(stream_key, tmp_payload)
            fs_list.append(tmp_payload[:FS_LENGTH])
            pubkey_list.append(tmp_payload[FS_LENGTH:
                                           FS_LENGTH + GROUP_ELEM_LENGTH])
            fs_payload = (tmp_payload[FS_LENGTH + GROUP_ELEM_LENGTH:] +
                          dropped_paddings.pop())
        assert fs_payload == initial_fs_payload
        return (fs_list, pubkey_list)

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
        if packet.get_type() != HornetPacketType.SETUP_BWD:
            return HornetProcessingResult(HornetProcessingResult.Type.INVALID)

        # Process the sphinx packet
        sphinx_packet = packet.sphinx_packet
        try:
            sphinx_processing_result = \
                self._sphinx_end_host.process_incoming_reply(sphinx_packet)
        except:
            return HornetProcessingResult(HornetProcessingResult.Type.INVALID)
        if not sphinx_processing_result.is_at_destination():
            return HornetProcessingResult(HornetProcessingResult.Type.INVALID)

        # Retrieve the session request information
        #FIXME:Daniele: Add protection against concurrent access
        reply_id = sphinx_processing_result.reply_id
        if reply_id not in self._session_requests_by_reply_id:
            return HornetProcessingResult(HornetProcessingResult.Type.INVALID)
        session_request_info = self._session_requests_by_reply_id[reply_id]
        if (session_request_info.expiration_time < time.time() or
                packet.expiration_time < time.time()):
            return HornetProcessingResult(
                        HornetProcessingResult.Type.SESSION_EXPIRED,
                        session_id=session_request_info.session_id)

        # Get the forwarding segments for the forward path
        fwd_fs_payload = self._sphinx_node.get_message_from_payload(
                                        sphinx_processing_result.result)
        try:
            fwd_fses, fwd_tmp_pubkeys = self._retrieve_fses_and_pubkeys(
                fwd_fs_payload,
                session_request_info.forward_path_data.shared_sphinx_keys,
                session_request_info.forward_path_data.initial_fs_payload)
        except _MacVerificationFailure:
            return HornetProcessingResult(HornetProcessingResult.Type.INVALID)

        # Get the forwarding segments for the backward path
        bwd_fs_payload = packet.fs_payload
        try:
            # The last shared_sphinx_key is not passed, as it is the key that
            # the source "shares with itself", but the source has not added
            # any forwarding segment to the fs payload it just received.
            bwd_fses, bwd_tmp_pubkeys = self._retrieve_fses_and_pubkeys(
                bwd_fs_payload,
                session_request_info.backward_path_data.shared_sphinx_keys[:
                                                                           -1],
                session_request_info.backward_path_data.initial_fs_payload)
        except _MacVerificationFailure:
            return HornetProcessingResult(HornetProcessingResult.Type.INVALID)
        

        #FIXME:Daniele: Finish method (the return is incorrect)
        return HornetProcessingResult(HornetProcessingResult.Type
                                      .SESSION_ESTABLISHED)


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
        payload = self._sphinx_node.get_message_from_payload(
                                        sphinx_processing_result.result)
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
        second_packet = SetupPacket(HornetPacketType.SETUP_BWD,
                                    packet.expiration_time,
                                    sphinx_reply_packet,
                                    new_fs_payload,
                                    first_hop=first_hop,
                                    max_hops=packet.max_hops)
        return HornetProcessingResult(HornetProcessingResult
                                      .Type.SESSION_REQUEST,
                                      packet_to_send=second_packet)


def test():
    # Source
    source_private = Private()
    source_secret_key = b's'*32
    source = HornetSource(source_secret_key, source_private)

    # Nodes
    node_1_private = Private()
    node_2_private = Private()
    node_1_secret_key = b'1'*32
    node_2_secret_key = b'2'*32
    node_1 = HornetNode(node_1_secret_key, node_1_private)
    node_2 = HornetNode(node_2_secret_key, node_2_private)

    # Destination
    dest_private = Private()
    dest_secret_key = b'd'*32
    destination = HornetDestination(dest_secret_key, dest_private)

    # Source session request
    fwd_path = [b'1'*16, b'2'*16, b'dest_address0000']
    bwd_path = [b'2'*16, b'1'*16, b'source_address00']
    fwd_pubkeys = [node_1_private.get_public(), node_2_private.get_public(),
                    destination.public]
    bwd_pubkeys = [fwd_pubkeys[1], fwd_pubkeys[0], source.public]
    session_expiration_time = int(time.time()) + 60
    sid, packet = source.create_new_session_request(fwd_path, fwd_pubkeys,
                                                    bwd_path, bwd_pubkeys,
                                                    session_expiration_time)
    assert isinstance(sid, int)
    assert packet.get_first_hop() == fwd_path[0]
    raw_packet = packet.pack()

    # Node 1 setup packet processing
    result = node_1.process_incoming_packet(raw_packet)
    assert result.result_type == HornetProcessingResult.Type.FORWARD
    new_packet = result.packet_to_send
    assert new_packet is not None
    assert new_packet.get_type() == HornetPacketType.SETUP_FWD
    #assert new_packet.max_hops == max_hops
    assert new_packet.expiration_time == session_expiration_time
    assert isinstance(new_packet.sphinx_packet, SphinxPacket)
    assert len(new_packet.fs_payload) == compute_fs_payload_size()
    assert new_packet.get_first_hop() == fwd_path[1]
    raw_packet = new_packet.pack()

    # Node 2 setup packet processing
    result = node_2.process_incoming_packet(raw_packet)
    assert result.result_type == HornetProcessingResult.Type.FORWARD
    new_packet = result.packet_to_send
    assert new_packet is not None
    assert new_packet.get_type() == HornetPacketType.SETUP_FWD
    #assert new_packet.max_hops == max_hops
    assert new_packet.expiration_time == session_expiration_time
    assert isinstance(new_packet.sphinx_packet, SphinxPacket)
    assert len(new_packet.fs_payload) == compute_fs_payload_size()
    assert new_packet.get_first_hop() == fwd_path[2]
    raw_packet = new_packet.pack()

    # Destination setup packet processing
    result = destination.process_incoming_packet(raw_packet)
    assert result.result_type == HornetProcessingResult.Type.SESSION_REQUEST
    new_packet = result.packet_to_send
    assert new_packet is not None
    assert new_packet.get_type() == HornetPacketType.SETUP_BWD
    #assert new_packet.max_hops == max_hops
    assert new_packet.expiration_time == session_expiration_time
    assert isinstance(new_packet.sphinx_packet, SphinxPacket)
    assert len(new_packet.fs_payload) == compute_fs_payload_size()
    assert new_packet.get_first_hop() == bwd_path[0]
    raw_packet = new_packet.pack()

    # Node 2 setup packet processing
    result = node_2.process_incoming_packet(raw_packet)
    assert result.result_type == HornetProcessingResult.Type.FORWARD
    new_packet = result.packet_to_send
    assert new_packet is not None
    assert new_packet.get_type() == HornetPacketType.SETUP_BWD
    #assert new_packet.max_hops == max_hops
    assert new_packet.expiration_time == session_expiration_time
    assert isinstance(new_packet.sphinx_packet, SphinxPacket)
    assert len(new_packet.fs_payload) == compute_fs_payload_size()
    assert new_packet.get_first_hop() == bwd_path[1]
    raw_packet = new_packet.pack()

    # Node 1 setup packet processing
    result = node_1.process_incoming_packet(raw_packet)
    assert result.result_type == HornetProcessingResult.Type.FORWARD
    new_packet = result.packet_to_send
    assert new_packet is not None
    assert new_packet.get_type() == HornetPacketType.SETUP_BWD
    #assert new_packet.max_hops == max_hops
    assert new_packet.expiration_time == session_expiration_time
    assert isinstance(new_packet.sphinx_packet, SphinxPacket)
    assert len(new_packet.fs_payload) == compute_fs_payload_size()
    assert new_packet.get_first_hop() == bwd_path[2]
    raw_packet = new_packet.pack()

    # Source processing of the second setup packet
    result = source.process_incoming_packet(raw_packet)
    assert (result.result_type ==
            HornetProcessingResult.Type.SESSION_ESTABLISHED)


if __name__ == "__main__":
    test()
