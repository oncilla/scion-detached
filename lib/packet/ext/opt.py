# Copyright 2015 ETH Zurich
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
:mod:`opt` --- OPT extension header and its handler
=================================================================
"""
# Stdlib
import struct

# SCION
from Crypto.Hash import SHA256

from lib.crypto.symcrypto import cbcmac, compute_session_key
from lib.packet.ext_hdr import HopByHopExtension
from lib.packet.packet_base import PayloadBase
from lib.packet.scion_addr import ISD_AS
from lib.util import Raw, SCIONTime
from lib.types import ExtHopByHopType


class OPTExt(HopByHopExtension):
    """
    0B       1        2        3        4        5        6        7
    +--------+--------+--------+--------+--------+--------+--------+--------+
    | xxxxxxxxxxxxxxxxxxxxxxxx |                    padding                 |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                               Session ID...                           |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                            ...Session ID                              |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                               DataHash...                             |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                            ...DataHash                                |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                                  PVF...                               |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                               ...PVF                                  |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    """
    NAME = "OPTExt"
    EXT_TYPE = ExtHopByHopType.OPT
    SESSION_ID_LEN = 16
    DATA_HASH_LEN = 16
    PVF_LEN = 16
    PADDING_LEN = 5
    LEN = PADDING_LEN + SESSION_ID_LEN + DATA_HASH_LEN + PVF_LEN

    def __init__(self, raw=None):
        """
        Initialize an instance of the class OPTExt

        :param raw:
        :type raw:
        """
        super().__init__()
        self.session_id = None
        self.data_hash = None
        self.pvf = None
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        """
        Parse payload.
        """
        data = Raw(raw, self.NAME, self.LEN)
        super()._parse(data)
        # drop padding
        data.pop(self.PADDING_LEN)

        self.session_id = data.pop(self.SESSION_ID_LEN)
        self.data_hash = data.pop(self.DATA_HASH_LEN)
        self.pvf = data.pop(self.PVF_LEN)

    @classmethod
    def from_values(cls, session_id, data_hash=None, pvf=None):
        """
        Construct extension
        :param session_id: Session ID
        :type session_id: bytes
        :param data_hash: Data hash
        :type data_hash: bytes
        :param pvf: Path verification Field
        :type pvf: bytes
        """
        inst = OPTExt()
        inst.session_id = session_id
        inst.data_hash = data_hash
        inst.pvf = pvf
        return inst

    def pack(self):
        packed = []
        packed.append(bytes(self.PADDING_LEN))
        packed.append(self.session_id)
        packed.append(self.data_hash)
        packed.append(self.pvf)
        raw = b"".join(packed)
        self._check_len(raw)
        return raw

    @staticmethod
    def compute_intermediate_pvf(session_key, pvf):
        """

        :param session_key:
        :param pvf:
        :return:
        """
        return cbcmac(session_key, pvf)

    def process(self, secret_value):
        """

        :param secret_value:
        :type secret_value: bytes
        :return:
        """
        session_key = compute_session_key(secret_value, self.session_id)
        self.pvf = self.compute_intermediate_pvf(session_key, self.pvf)
        return []

    @staticmethod
    def compute_data_hash(payload):
        """

        :param payload:
        :type payload: PayloadBase
        :return:
        """
        assert isinstance(payload, PayloadBase)
        # TODO(rsd) use better hash function ?
        return SHA256.new(payload.pack()).digest()[:16]

    def set_data_hash(self, payload):
        """

        :param payload:
        :type payload: PayloadBase
        :return:
        """
        self.data_hash = self.compute_data_hash(payload)

    @staticmethod
    def compute_initial_pvf(session_key_dst, data_hash):
        return cbcmac(session_key_dst, data_hash)

    def set_initial_pvf(self, session_key_dst, payload=None):
        """

        :param session_key_dst:
        :param payload:
        :return:
        """

        if payload:
            self.set_data_hash(payload)
        assert self.data_hash
        self.pvf = self.compute_initial_pvf(session_key_dst, self.data_hash)
    def __str__(self):
        return ('%s(%sB):\nsession id:%s\ndata hash:%s\npvf: %s' % (self.NAME, len(self),
                                                                    self.session_id, self.data_hash, self.pvf))
