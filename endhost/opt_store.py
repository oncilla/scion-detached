# Copyright 2016 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`opt_store` --- OPT store
===========================================
"""
import logging

from lib.packet.ext.opt import OPTExt
from lib.packet.packet_base import PayloadRaw, PayloadBase
from lib.packet.scion import SCIONL4Packet, build_base_hdrs
from lib.packet.scion_addr import SCIONAddr
from lib.packet.scion_udp import SCIONUDPHeader


class OPTCreatePacketParams(object):

    session_id = None  # bytes (16b)
    payload = None  # PayloadBase
    session_key_dst = None  # bytes (16b)
    dst = None  # SCIONAddr
    src = None  # SCIONAddr
    port_dst = None  # int
    port_src = None  # int
    path = None  # PathBase


class OPTStore(object):
    """

    """

    def __init__(self):
        self._tuple_map = dict()  # mapping {session_id -> [(data hash, pvf)]} used to verify


    @staticmethod
    def get_opt_ext_hdr(pkt):
        """

        :param pkt:
        :type pkt: SCIONL4Packet
        :return:
        """
        for ext_hdr in pkt.ext_hdrs:
            if ext_hdr.EXT_TYPE == OPTExt.EXT_TYPE:
                assert isinstance(ext_hdr, OPTExt)
                return ext_hdr
        return None

    @staticmethod
    def create_scion_udp_packet(params):
        """

        :return:
        """
        assert isinstance(params, OPTCreatePacketParams)
        assert isinstance(params.payload, PayloadBase)
        assert isinstance(params.src, SCIONAddr)
        assert isinstance(params.dst, SCIONAddr)

        opt_ext = OPTExt.from_values(params.session_id)
        opt_ext.set_initial_pvf(params.session_key_dst, params.payload)
        cmn_hdr, addr_hdr = build_base_hdrs(params.src, params.dst)
        udp_hdr = SCIONUDPHeader.from_values(params.src, params.port_src,
                                             params.dst, params.port_dst,
                                             params.payload)
        return SCIONL4Packet.from_values(cmn_hdr, addr_hdr, params.path,
                                     [opt_ext], udp_hdr, params.payload)

    @staticmethod
    def is_hash_valid(pkt):
        """

        :param pkt:
        :type pkt: SCIONL4Packet
        :return:
        """
        assert isinstance(pkt, SCIONL4Packet)

        ext_hdr = OPTStore.get_opt_ext_hdr(pkt)
        if ext_hdr:
            return OPTExt.compute_data_hash(pkt.get_payload()) == ext_hdr.data_hash
        return True

    def insert_packet(self, pkt):
        """

        :param pkt:
        :type pkt: SCIONL4Packet
        :return:
        """

        assert isinstance(pkt, SCIONL4Packet)

        ext_hdr = OPTStore.get_opt_ext_hdr(pkt)
        if ext_hdr:
            if ext_hdr.session_id in self._tuple_map:
                self._tuple_map[ext_hdr.session_id].append((ext_hdr.data_hash, ext_hdr.pvf))
            else:
                self._tuple_map[ext_hdr.session_id] = [(ext_hdr.data_hash, ext_hdr.pvf)]

    def pop_session(self, session_id):
        """

        :param session_id:
        :type session_id: bytes
        :return:
        """
        return self._tuple_map.pop(session_id, None)

    @staticmethod
    def _validate_tuple(tup, drkeys):
        """

        :param tup:
        :type tup: (bytes, bytes)
        :param drkeys:
        :type drkeys: [bytes]
        :return:
        """

        pvf = OPTExt.compute_initial_pvf(drkeys[-1], tup[0])
        logging.critical("Original pvf %s", pvf)

        # last key is the dst key
        for key in drkeys[:-1]:
            assert isinstance(key, bytes) and len(key) == 16
            pvf = OPTExt.compute_intermediate_pvf(key, pvf)
            logging.critical("\n\tpvf: %s\nor\tpvf: %s\nkey: %s", pvf, tup[1], key)

        return pvf == tup[1]

    def validate_session(self, session_id, drkeys):
        """

        :param session_id:
        :type session_id: bytes
        :param drkeys:
        :type drkeys: [bytes]
        :return:
        """

        for tup in self._tuple_map[session_id]:
            if not self._validate_tuple(tup, drkeys):
                return False
        return True
