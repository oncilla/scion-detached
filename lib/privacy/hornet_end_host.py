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
from lib.privacy.hornet_node import HornetNode, InvalidCarriedStateException
from lib.privacy.sphinx.sphinx_end_host import SphinxEndHost,\
    compute_shared_keys
import uuid
from curve25519.keys import Private, Public
from lib.privacy.session import SetupPathData, SessionRequestInfo,\
    TransmissionPathData, SessionInfo, SourceSessionInfo,\
    DestinationSessionInfo
from lib.privacy.hornet_packet import compute_fs_payload_size, SetupPacket,\
    HornetPacketType, SHARED_KEY_LENGTH, FS_LENGTH,\
    compute_blinded_aheader_size,\
    AnonymousHeader, NONCE_LENGTH, DATA_PAYLOAD_LENGTH, DataPacket,\
    ROUTING_INFO_LENGTH
from lib.privacy.hornet_crypto_util import generate_initial_fs_payload,\
    derive_fs_payload_stream_key, derive_fs_payload_mac_key,\
    derive_aheader_stream_key, derive_aheader_mac_key, derive_new_nonce,\
    derive_data_payload_stream_key, derive_previous_nonce
import os
import time
from lib.privacy.hornet_processing import HornetProcessingResult
from lib.privacy.common.exception import PacketParsingException
from lib.privacy.sphinx.packet import SphinxHeader, SphinxPacket
from lib.privacy.common.constants import LOCALHOST_ADDRESS,\
    DEFAULT_ADDRESS_LENGTH, GROUP_ELEM_LENGTH, MAC_SIZE, DEFAULT_MAX_HOPS
import itertools
from lib.privacy.sphinx.sphinx_crypto_util import stream_cipher_encrypt,\
    verify_mac, stream_cipher_decrypt, compute_mac, pad_to_length,\
    remove_length_pad, PaddingFormatError
import copy


class _MacVerificationFailure(Exception):
    """
    Exception indicating the failed verification of a Message Authentication
    Code (MAC).
    """
    pass


class InvalidSession(Exception):
    """
    Exception raised when an attempt is made to access a session which does
    not exist
    """
    pass


class HornetEndHost():
    """
    Abstract base class for a Hornet end host, source or destination.
    """

    def __init__(self):
        self._open_sessions_by_fs = dict()
        self._open_sessions_by_session_id = dict()

    def add_session_info(self, session_info):
        """
        Store a :class:`session.SessionInfo` instance for a new session.
        """
        assert isinstance(session_info, SessionInfo)
        assert (session_info.forwarding_segment not in
                self._open_sessions_by_fs), ("forwarding segment already "
                                             "associated with an existing "
                                             "session")
        self._open_sessions_by_session_id[session_info.session_id] = \
            session_info
        self._open_sessions_by_fs[session_info.forwarding_segment] = \
            session_info

    def remove_session_info(self, session_id=None, forwarding_segment=None):
        """
        Remove a :class:`session.SessionInfo` instance identified
        through its session id or forwarding segment. This method does nothing
        if the given id or forwarding segment is not associated to any
        existing session.
        """
        assert [session_id, forwarding_segment].count(None) == 1
        if (session_id is not None and
            session_id in self._open_sessions_by_session_id):
            assert isinstance(session_id, int)
            forwarding_segment = (self._open_sessions_by_session_id[session_id]
                                  .forwarding_segment)
        elif (forwarding_segment is not None and
              forwarding_segment in self._open_sessions_by_fs):
            assert isinstance(forwarding_segment, bytes)
            session_id = (self._open_sessions_by_fs[forwarding_segment]
                          .session_id)
        else:
            return # session_id already deleted
        del self._open_sessions_by_session_id[session_id]
        del self._open_sessions_by_fs[forwarding_segment]



class HornetSource(HornetEndHost, HornetNode):
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

    def __init__(self, secret_key, private, public=None, max_hops=DEFAULT_MAX_HOPS):
        assert isinstance(secret_key, bytes)
        self._sphinx_end_host = SphinxEndHost(private, public)
        self._sphinx_end_host.max_hops = max_hops
        HornetEndHost.__init__(self)
        HornetNode.__init__(self, secret_key,
                            sphinx_node=self._sphinx_end_host,
                            max_hops=max_hops)
        self._session_requests_by_reply_id = dict()
        self._session_requests_by_session_id = dict()

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
        Remove a :class:`session.SessionRequestInfo` instance identified
        through its session id or reply id. This method does nothing if the
        given id is not associated to any existing session request.
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
                                   valid_for_seconds=None):
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

    def construct_data_packet(self, session_id, data,
                              packet_type=HornetPacketType.DATA_FWD):
        """
        Construct a :class:`hornet_packet.DataPacket` to be sent belonging
        to the specified session.
        """
        assert isinstance(session_id, int)
        assert isinstance(packet_type, int)
        assert packet_type in HornetPacketType.DATA_TYPES
        assert isinstance(data, bytes)
        if session_id not in self._open_sessions_by_session_id:
            raise InvalidSession("session id " + str(session_id) +
                                 " does not correspond to any open session")
        session_info = self._open_sessions_by_session_id[session_id]
        assert isinstance(session_info, SourceSessionInfo)
        if session_info.expiration_time <= int(time.time()):
            raise InvalidSession("session with id " + str(session_id) +
                                 " has expired")
        # Set values for new header (deep copy is mainly to avoid issued with
        # concurrent execution of this method, changing these values
        # in the stored AnonymousHeader would not be a problem otherwise
        header = copy.deepcopy(session_info.forward_path_data.anonymous_header)
        header.packet_type = packet_type
        new_nonce = os.urandom(NONCE_LENGTH)
        header.nonce = new_nonce

        # Construct the onion-encrypted payload
        shared_keys = session_info.forward_path_data.shared_keys
        received_nonce = new_nonce
        nonces = [] # New nonces as derived at every hop by the nodes and dest
        for shared_key in shared_keys:
            received_nonce = derive_new_nonce(shared_key, received_nonce)
            nonces.append(received_nonce)
        stream_keys = [derive_data_payload_stream_key(shared_key)
                       for shared_key in shared_keys]
        payload = pad_to_length(data, DATA_PAYLOAD_LENGTH)
        for stream_key, nonce in zip(reversed(stream_keys), reversed(nonces)):
            payload = stream_cipher_encrypt(stream_key, payload, nonce)

        # Return the new data packet
        return DataPacket(header, payload)

    @staticmethod
    def _compute_session_shared_keys(source_tmp_private, blinding_factors,
                                     nodes_tmp_pubkeys):
        """
        Compute the shared keys between the source and the nodes on a path
        given the initial temporary private key used by the source, the
        blinding factors, and the temporary public keys sent by the nodes
        in the FS payload.
        """
        assert isinstance(source_tmp_private, Private)
        shared_keys = []

        for i, node_pubkey in enumerate(nodes_tmp_pubkeys):
            if not isinstance(node_pubkey, Public):
                node_pubkey = Public(node_pubkey)
            tmp_pubkey = node_pubkey
            for blinding_factor in blinding_factors[:i]:
                tmp_pubkey = blinding_factor.get_shared_public(tmp_pubkey)
            full_shared_key = source_tmp_private.get_shared_key(tmp_pubkey)
            shared_keys.append(full_shared_key[:SHARED_KEY_LENGTH])
        return shared_keys

    def _construct_basic_anonymous_header(self, shared_keys,
                                          forwarding_segments):
        """
        Construct the fundamental part of an anonymous header
        (:class:`hornet_packet.AnonymousHeader`), which consists in the
        following triple: (first_fs, first_mac, blinded_aheader), and return
        these values together with the last hop mac and blinded header
        (necessary for the source to do a fast verification of incoming data
        packets. The output is the following tuple:
        (first_fs, first_mac, blinded_aheader, last_mac, last_blinded_header)
        """
        assert len(shared_keys) == len(forwarding_segments)
        for shared_key in shared_keys:
            assert isinstance(shared_key, bytes)
            assert len(shared_key) == SHARED_KEY_LENGTH
        pad_size = FS_LENGTH + MAC_SIZE
        blinded_aheader_size = \
            compute_blinded_aheader_size(self._sphinx_end_host.max_hops)
        aheader_size = pad_size + blinded_aheader_size
        number_of_hops = len(shared_keys)
        stream_keys = [derive_aheader_stream_key(shared_key)
                       for shared_key in shared_keys]
        mac_keys = [derive_aheader_mac_key(shared_key)
                    for shared_key in shared_keys]

        # Create filler string
        long_filler = b'\0' * aheader_size
        for stream_key in stream_keys[:-1]:
            long_filler = long_filler[pad_size:] + b'\0'*pad_size
            long_filler = stream_cipher_decrypt(stream_key, long_filler)
        filler_length = pad_size * (number_of_hops - 1)
        filler = long_filler[-filler_length:]

        # Compute the anonymous header at each hop, starting by the last,
        # performing the reverse process of the anonymous header decryption
        # that will be done by the nodes
        last_blinded_aheader = (os.urandom(blinded_aheader_size -
                                           filler_length) + filler)
        last_fs = forwarding_segments[-1]
        last_mac = compute_mac(mac_keys[-1], last_fs + last_blinded_aheader)
        a_header = last_fs + last_mac + last_blinded_aheader
        for fs, stream_key, mac_key in zip(reversed(forwarding_segments[:-1]),
                                           reversed(stream_keys[:-1]),
                                           reversed(mac_keys[:-1])):
            padded_blinded_aheader = stream_cipher_encrypt(stream_key,
                                                           a_header)
            blinded_aheader = padded_blinded_aheader[:-pad_size]
            assert padded_blinded_aheader[-pad_size:] == b'\0'*pad_size
            mac = compute_mac(mac_key, fs + blinded_aheader)
            a_header = fs + mac + blinded_aheader
        return (fs, mac, blinded_aheader, last_mac, last_blinded_aheader)

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
        fs_list.reverse()
        pubkey_list.reverse()
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
        try:
            fwd_fs_payload = self._sphinx_node.get_message_from_payload(
                                            sphinx_processing_result.result)
        except PaddingFormatError:
            return HornetProcessingResult(HornetProcessingResult.Type.INVALID)
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

        # Compute the new shared keys (forward secrecy)
        fwd_shared_keys = self._compute_session_shared_keys(
            session_request_info.forward_path_data.source_private,
            session_request_info.forward_path_data.blinding_factors,
            fwd_tmp_pubkeys)
        bwd_shared_keys = self._compute_session_shared_keys(
            session_request_info.backward_path_data.source_private,
            session_request_info.backward_path_data.blinding_factors,
            bwd_tmp_pubkeys)
        
        # Add, for the backward path, the source's dummy forwarding segment
        # and shared_key
        source_dummy_fs = os.urandom(FS_LENGTH)
        bwd_fses.append(source_dummy_fs)
        source_shared_key = os.urandom(SHARED_KEY_LENGTH)
        bwd_shared_keys.append(source_shared_key)

        # Compute forward anonymous header and transmission path data
        (fs, mac, blinded_aheader, _, _) = \
            self._construct_basic_anonymous_header(fwd_shared_keys, fwd_fses)
        fwd_path = session_request_info.forward_path_data.path
        fwd_anonymous_header = AnonymousHeader(
            packet_type=HornetPacketType.DATA_FWD, nonce=b'\0'*NONCE_LENGTH,
            current_fs=fs, current_mac=mac, blinded_aheader=blinded_aheader,
            first_hop=fwd_path[0],
            max_hops=self._sphinx_end_host.max_hops)
        fwd_path_data = TransmissionPathData(fwd_anonymous_header,
                                             fwd_shared_keys, fwd_path)
        # Compute backward anonymous header and transmission path data
        (fs, mac, blinded_aheader, incoming_mac, incoming_blinded_aheader) = \
            self._construct_basic_anonymous_header(bwd_shared_keys, bwd_fses)
        bwd_path = session_request_info.backward_path_data.path
        bwd_anonymous_header = AnonymousHeader(
            packet_type=HornetPacketType.DATA_BWD, nonce=b'\0'*NONCE_LENGTH,
            current_fs=fs, current_mac=mac, blinded_aheader=blinded_aheader,
            first_hop=session_request_info.backward_path_data.path[0],
            max_hops=self._sphinx_end_host.max_hops)
        bwd_path_data = TransmissionPathData(bwd_anonymous_header,
                                             bwd_shared_keys, bwd_path)

        # Store session and delete session request information
        #FIXME:Daniele: Add protection against concurrent access
        session_info = SourceSessionInfo(session_request_info.session_id,
                                         fwd_path_data, bwd_path_data,
                                         source_dummy_fs, incoming_mac,
                                         incoming_blinded_aheader)
        self.add_session_info(session_info)
        self.remove_session_request_info(session_id=
                                         session_request_info.session_id)

        # Create data packet to deliver the backward header to the destination
        data_for_destination = bwd_path[0] + bwd_anonymous_header.pack()
        try:
            next_packet = \
                self.construct_data_packet(session_request_info.session_id,
                                           data_for_destination,
                                           HornetPacketType.DATA_FWD_SESSION)
        except InvalidSession:
            return HornetProcessingResult(
                        HornetProcessingResult.Type.SESSION_EXPIRED,
                        session_id=session_request_info.session_id)

        return HornetProcessingResult(HornetProcessingResult.Type
                                      .SESSION_ESTABLISHED,
                                      session_request_info.session_id,
                                      packet_to_send=next_packet)

    def process_data_packet(self, raw_packet):
        """
        Process an incoming Hornet data packet
        (:class:`hornet_packet.DataPacket`), and return an instance of class
        :class:`hornet_processing.HornetProcessingResult`.
        """
        try:
            packet = DataPacket.parse_bytes_to_packet(raw_packet)
        except PacketParsingException:
            return HornetProcessingResult(HornetProcessingResult.Type.INVALID)

        forwarding_segment = packet.header.current_fs
        mac = packet.header.current_mac
        blinded_header = packet.header.blinded_aheader
        if forwarding_segment not in self._open_sessions_by_fs:
            return HornetProcessingResult(HornetProcessingResult.
                                          Type.INVALID)
        session_info = self._open_sessions_by_fs[forwarding_segment]
        assert isinstance(session_info, SourceSessionInfo)
        if session_info.expiration_time <= int(time.time()):
            return HornetProcessingResult(
                HornetProcessingResult.Type.SESSION_EXPIRED,
                session_id=session_info.session_id)
        if (session_info.incoming_mac != mac or
                session_info.incoming_blinded_aheader != blinded_header):
            return HornetProcessingResult(HornetProcessingResult.
                                          Type.INVALID)

        # Construct the onion-encrypted payload
        # The shared keys are those of the nodes that encrypted the payload,
        # from first to last, i.e. from the destination to the node closest
        # to the destination. The last key in
        # session_info.backward_path_data.shared_keys is the key the source
        # "shared with itself", so it is discarded since the source has
        # obviously not encrypted the payload.
        destination_shared_key = session_info.forward_path_data.shared_keys[-1]
        shared_keys = [destination_shared_key]
        shared_keys.extend(session_info.backward_path_data.shared_keys[:-1])
        nonce = packet.header.nonce
        payload = packet.payload
        for shared_key in reversed(shared_keys):
            stream_key = derive_data_payload_stream_key(shared_key)
            payload = stream_cipher_decrypt(stream_key, payload, nonce)
            nonce = derive_previous_nonce(shared_key, nonce)
        try:
            data = remove_length_pad(payload)
        except PaddingFormatError:
            return HornetProcessingResult(HornetProcessingResult.
                                          Type.INVALID)

        return HornetProcessingResult(HornetProcessingResult.Type.
                                      RECEIVED_DATA,
                                      session_id=session_info.session_id,
                                      received_data=data)


class HornetDestination(HornetEndHost, HornetNode):
    """
    A Hornet destination.

    :ivar secret_key: secret key of the HornetNode (SV in the paper)
    :vartype secret_key: bytes
    :ivar private: private key of the HornetNode
    :vartype private: bytes or :class:`curve25519.keys.Private`
    :ivar public: public key of the HornetNode
    :vartype public: bytes
    """

    def __init__(self, secret_key, private, public=None, max_hops=DEFAULT_MAX_HOPS):
        assert isinstance(secret_key, bytes)
        HornetEndHost.__init__(self)
        HornetNode.__init__(self, secret_key, private=private, max_hops=max_hops)

    def construct_data_packet(self, session_id, data):
        """
        Construct a :class:`hornet_packet.DataPacket` to be sent belonging
        to the specified session.
        """
        assert isinstance(session_id, int)
        assert isinstance(data, bytes)
        if session_id not in self._open_sessions_by_session_id:
            raise InvalidSession("session id " + str(session_id) +
                                 " does not correspond to any open session")
        session_info = self._open_sessions_by_session_id[session_id]
        assert isinstance(session_info, DestinationSessionInfo)
        if session_info.expiration_time <= int(time.time()):
            raise InvalidSession("session with id " + str(session_id) +
                                 " has expired")
        # Set values for new header (deep copy is mainly to avoid issued with
        # concurrent execution of this method, changing these values
        # in the stored AnonymousHeader would not be a problem otherwise
        header = copy.deepcopy(session_info.backward_anonymous_header)
        header.packet_type = HornetPacketType.DATA_BWD
        new_nonce = os.urandom(NONCE_LENGTH)
        header.nonce = new_nonce

        # Encrypt the payload
        stream_key = derive_data_payload_stream_key(session_info.shared_key)
        payload = pad_to_length(data, DATA_PAYLOAD_LENGTH)
        payload = stream_cipher_encrypt(stream_key, payload, new_nonce)

        # Return the new data packet
        return DataPacket(header, payload)

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
        try:
            payload = self._sphinx_node.get_message_from_payload(
                                        sphinx_processing_result.result)
        except PaddingFormatError:
            return HornetProcessingResult(HornetProcessingResult.Type.INVALID)
        first_hop = payload[:DEFAULT_ADDRESS_LENGTH]
        raw_header = payload[DEFAULT_ADDRESS_LENGTH:]
        bwd_sphinx_header = SphinxHeader.parse_bytes_to_header(raw_header,
            max_hops=self._sphinx_node.max_hops)
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

    def process_data_packet(self, raw_packet):
        """
        Process an incoming Hornet data packet
        (:class:`hornet_packet.DataPacket`), and return an instance of class
        :class:`hornet_processing.HornetProcessingResult`.
        """
        try:
            packet = DataPacket.parse_bytes_to_packet(raw_packet)
        except PacketParsingException:
            return HornetProcessingResult(HornetProcessingResult.Type.INVALID)

        forwarding_segment = packet.header.current_fs
        mac = packet.header.current_mac
        blinded_header = packet.header.blinded_aheader
        if packet.get_type() == HornetPacketType.DATA_FWD_SESSION:
            if forwarding_segment in self._open_sessions_by_fs:
                # The forwarding segment corresponds to an already open session
                #TODO:Daniele: for now this is not supported, but here would be
                # the point where to handle an update of the backward header
                # requested by the source.
                return HornetProcessingResult(HornetProcessingResult.
                                              Type.INVALID)
            # Retrieve the shared key and verify the integrity of the header,
            # and retrieve also the rest of the encrypted state - routing info
            # and expiration time - checking that the session has not expired
            try:
                shared_key, routing_info, expiration_time = \
                    self.decrypt_forwarding_segment(forwarding_segment, mac,
                                                    blinded_header)
            except InvalidCarriedStateException:
                return HornetProcessingResult(HornetProcessingResult.
                                              Type.INVALID)
            if routing_info != LOCALHOST_ADDRESS:
                #TODO:Daniele: Log this, should not happen
                assert False, "Valid FS indicating forwarding encountered"
                return HornetProcessingResult(HornetProcessingResult.
                                              Type.INVALID)

            # Retrieve backward header from the payload
            payload_stream_key = derive_data_payload_stream_key(shared_key)
            nonce = derive_new_nonce(shared_key, packet.header.nonce)
            payload = stream_cipher_decrypt(payload_stream_key, packet.payload,
                                            nonce)
            try:
                payload = remove_length_pad(payload)
            except PaddingFormatError:
                return HornetProcessingResult(HornetProcessingResult.
                                              Type.INVALID)
            if len(payload) < DEFAULT_ADDRESS_LENGTH:
                return HornetProcessingResult(HornetProcessingResult.
                                              Type.INVALID)
            bwd_first_hop = payload[:DEFAULT_ADDRESS_LENGTH]
            raw_bwd_header = payload[DEFAULT_ADDRESS_LENGTH:]
            try:
                bwd_header = (
                    AnonymousHeader.parse_bytes_to_header(raw_bwd_header))
            except PacketParsingException:
                return HornetProcessingResult(HornetProcessingResult.
                                              Type.INVALID)
            bwd_header.first_hop = bwd_first_hop

            # Construct new DestinationSessionInfo object and store it
            # pylint: disable=no-member
            new_session_id = uuid.uuid4().int
            # pylint: enable=no-member
            session_info = DestinationSessionInfo(new_session_id, shared_key,
                                                  forwarding_segment, mac,
                                                  blinded_header, bwd_header,
                                                  expiration_time)
            self.add_session_info(session_info)

            # Return to the caller informing it of the establishment of a new
            # session, providing the new session id
            return HornetProcessingResult(HornetProcessingResult.Type.
                                          SESSION_ESTABLISHED, new_session_id)
        elif packet.get_type() == HornetPacketType.DATA_FWD:
            # Check if the packet header corresponds to a valid session
            if forwarding_segment not in self._open_sessions_by_fs:
                return HornetProcessingResult(HornetProcessingResult.
                                              Type.INVALID)
            session_info = self._open_sessions_by_fs[forwarding_segment]
            assert isinstance(session_info, DestinationSessionInfo)
            if session_info.expiration_time <= int(time.time()):
                return HornetProcessingResult(
                    HornetProcessingResult.Type.SESSION_EXPIRED,
                    session_id=session_info.session_id)
            if (session_info.incoming_mac != mac or
                    session_info.incoming_blinded_aheader != blinded_header):
                return HornetProcessingResult(HornetProcessingResult.
                                              Type.INVALID)

            # Get data from payload
            shared_key = session_info.shared_key
            payload_stream_key = derive_data_payload_stream_key(shared_key)
            nonce = derive_new_nonce(shared_key, packet.header.nonce)
            payload = stream_cipher_decrypt(payload_stream_key, packet.payload,
                                            nonce)
            try:
                data = remove_length_pad(payload)
            except PaddingFormatError:
                return HornetProcessingResult(HornetProcessingResult.
                                              Type.INVALID)

            return HornetProcessingResult(HornetProcessingResult.Type.
                                          RECEIVED_DATA,
                                          session_id=session_info.session_id,
                                          received_data=data)
        else:
            return HornetProcessingResult(HornetProcessingResult.
                                              Type.INVALID)



def test(number_of_hops=5, max_hops=DEFAULT_MAX_HOPS):
    assert number_of_hops <= max_hops
    number_of_intermediate_nodes = number_of_hops - 1

    # Source
    source_private = Private(secret=b'S'*32)
    source = HornetSource(os.urandom(32), source_private, max_hops=max_hops)

    # Nodes
    path = []
    nodes = []
    for _ in range(number_of_intermediate_nodes):
        private = Private(secret=os.urandom(32))
        nodes.append(HornetNode(os.urandom(32), private, max_hops=max_hops))
        path.append(os.urandom(DEFAULT_ADDRESS_LENGTH))
    node_pubkeys = [node.private.get_public() for node in nodes]

    # Destination
    dest_private = Private(secret=b'D'*32)
    destination = HornetDestination(os.urandom(32), dest_private,
                                    max_hops=max_hops)

    # Source session request
    fwd_path = path + [b'dest_address0000']
    bwd_path = path[::-1] + [b'source_address00']
    fwd_pubkeys = node_pubkeys + [destination.public]
    bwd_pubkeys = node_pubkeys[::-1] + [source.public]
    session_expiration_time = int(time.time()) + 600
    sid, packet = source.create_new_session_request(fwd_path, fwd_pubkeys,
                                                    bwd_path, bwd_pubkeys,
                                                    session_expiration_time)
    assert isinstance(sid, int)
    assert packet.get_first_hop() == fwd_path[0]
    raw_packet = packet.pack()

    # Nodes setup packet processing
    for i, node in enumerate(nodes):
        result = node.process_incoming_packet(raw_packet)
        assert result.result_type == HornetProcessingResult.Type.FORWARD
        new_packet = result.packet_to_send
        assert new_packet is not None
        assert new_packet.get_type() == HornetPacketType.SETUP_FWD
        #assert new_packet.max_hops == max_hops
        assert new_packet.expiration_time == session_expiration_time
        assert isinstance(new_packet.sphinx_packet, SphinxPacket)
        assert (len(new_packet.fs_payload) ==
                compute_fs_payload_size(max_hops=max_hops))
        assert new_packet.get_first_hop() == fwd_path[i+1]
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
    assert (len(new_packet.fs_payload) ==
            compute_fs_payload_size(max_hops=max_hops))
    assert new_packet.get_first_hop() == bwd_path[0]
    raw_packet = new_packet.pack()

    # Nodes setup packet processing
    for i, node in enumerate(reversed(nodes)):
        result = node.process_incoming_packet(raw_packet)
        assert result.result_type == HornetProcessingResult.Type.FORWARD
        new_packet = result.packet_to_send
        assert new_packet is not None
        assert new_packet.get_type() == HornetPacketType.SETUP_BWD
        #assert new_packet.max_hops == max_hops
        assert new_packet.expiration_time == session_expiration_time
        assert isinstance(new_packet.sphinx_packet, SphinxPacket)
        assert (len(new_packet.fs_payload) ==
                compute_fs_payload_size(max_hops=max_hops))
        assert new_packet.get_first_hop() == bwd_path[i+1]
        raw_packet = new_packet.pack()

    # Source processing of the second setup packet
    result = source.process_incoming_packet(raw_packet)
    assert (result.result_type ==
            HornetProcessingResult.Type.SESSION_ESTABLISHED)
    source_session_id = result.session_id
    assert source_session_id == sid
    new_packet = result.packet_to_send
    assert new_packet is not None
    assert new_packet.get_type() == HornetPacketType.DATA_FWD_SESSION
    assert len(new_packet.header.nonce) == NONCE_LENGTH
    assert new_packet.header.nonce != b'\0'*16
    assert len(new_packet.header.current_fs) == FS_LENGTH
    assert len(new_packet.header.current_mac) == MAC_SIZE
    assert (len(new_packet.header.blinded_aheader) ==
            compute_blinded_aheader_size(max_hops=max_hops))
    assert new_packet.get_first_hop() == fwd_path[0]
    previous_nonce = new_packet.header.nonce
    raw_packet = new_packet.pack()

    # Nodes data packet processing
    for i, node in enumerate(nodes):
        result = node.process_incoming_packet(raw_packet)
        assert result.result_type == HornetProcessingResult.Type.FORWARD
        new_packet = result.packet_to_send
        assert new_packet is not None
        assert new_packet.get_type() == HornetPacketType.DATA_FWD_SESSION
        assert len(new_packet.header.nonce) == NONCE_LENGTH
        assert new_packet.header.nonce != b'\0'*16
        assert new_packet.header.nonce != previous_nonce
        assert len(new_packet.header.current_fs) == FS_LENGTH
        assert len(new_packet.header.current_mac) == MAC_SIZE
        assert (len(new_packet.header.blinded_aheader) ==
                compute_blinded_aheader_size(max_hops=max_hops))
        assert new_packet.get_first_hop() == fwd_path[i+1]
        previous_nonce = new_packet.header.nonce
        raw_packet = new_packet.pack()

    # Destination data packet processing
    result = destination.process_incoming_packet(raw_packet)
    assert (result.result_type ==
            HornetProcessingResult.Type.SESSION_ESTABLISHED)
    dest_session_id = result.session_id
    assert dest_session_id

    # Source sends data to destination
    fwd_data = b'Data message for the destination'
    data_packet = source.construct_data_packet(source_session_id, fwd_data)
    assert data_packet.get_first_hop() == fwd_path[0]
    raw_packet = data_packet.pack()

    # Nodes data packet processing
    for i, node in enumerate(nodes):
        result = node.process_incoming_packet(raw_packet)
        assert result.result_type == HornetProcessingResult.Type.FORWARD
        new_packet = result.packet_to_send
        assert new_packet is not None
        assert new_packet.get_type() == HornetPacketType.DATA_FWD
        assert len(new_packet.header.nonce) == NONCE_LENGTH
        assert new_packet.header.nonce != b'\0'*16
        assert new_packet.header.nonce != previous_nonce
        assert len(new_packet.header.current_fs) == FS_LENGTH
        assert len(new_packet.header.current_mac) == MAC_SIZE
        assert (len(new_packet.header.blinded_aheader) ==
                compute_blinded_aheader_size(max_hops=max_hops))
        assert new_packet.get_first_hop() == fwd_path[i+1]
        previous_nonce = new_packet.header.nonce
        raw_packet = new_packet.pack()

    # Destination data packet processing
    result = destination.process_incoming_packet(raw_packet)
    assert (result.result_type ==
            HornetProcessingResult.Type.RECEIVED_DATA)
    assert result.session_id == dest_session_id
    assert result.received_data == fwd_data

    # Destination sends data to the source
    bwd_data = b'Data message for the source'
    data_packet = destination.construct_data_packet(dest_session_id, bwd_data)
    assert data_packet.get_first_hop() == bwd_path[0]
    raw_packet = data_packet.pack()

    # Nodes data packet processing
    for i, node in enumerate(reversed(nodes)):
        result = node.process_incoming_packet(raw_packet)
        assert result.result_type == HornetProcessingResult.Type.FORWARD
        new_packet = result.packet_to_send
        assert new_packet is not None
        assert new_packet.get_type() == HornetPacketType.DATA_BWD
        assert len(new_packet.header.nonce) == NONCE_LENGTH
        assert new_packet.header.nonce != b'\0'*16
        assert new_packet.header.nonce != previous_nonce
        assert len(new_packet.header.current_fs) == FS_LENGTH
        assert len(new_packet.header.current_mac) == MAC_SIZE
        assert (len(new_packet.header.blinded_aheader) ==
                compute_blinded_aheader_size(max_hops=max_hops))
        assert new_packet.get_first_hop() == bwd_path[i+1]
        previous_nonce = new_packet.header.nonce
        raw_packet = new_packet.pack()

    # Source data packet processing
    result = source.process_incoming_packet(raw_packet)
    assert (result.result_type ==
            HornetProcessingResult.Type.RECEIVED_DATA)
    assert result.session_id == source_session_id
    assert result.received_data == bwd_data


if __name__ == "__main__":
    test()
    test(number_of_hops=3, max_hops=5)
    test(number_of_hops=7, max_hops=9)
