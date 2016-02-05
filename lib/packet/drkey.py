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
:mod:`drkey` --- DRKey packets
============================================

Contains all the packet formats used for path management.
"""
# Stdlib
import struct
from collections import defaultdict

# SCION
from lib.types import PathMgmtType as PMT, PathSegmentType as PST
from lib.errors import SCIONParseError
from lib.packet.packet_base import PathMgmtPayloadBase
from lib.packet.pcb import PathSegment
from lib.packet.scion_addr import ISD_AD
from lib.packet.rev_info import RevocationInfo
from lib.util import Raw

from lib.types import TypeBase


class DRKeyType(TypeBase):
    """
    Enum of drkey packet types.
    """
    REQUEST_KEY = 0
    REPLY_KEY = 1
    SEND_KEY = 2
    ACKNOWLEDGE_KEY = 3


class DRKeyConstants(object):
    """
    Constants for drkey.
    """
    PRIVATE_KEY_BYTE_LENGTH = 16 # TODO only placeholder
    SESSION_ID_BYTE_LENGTH = 16


class DRKeyRequestKey(object):
    """
    TODO
    """
    NAME = "DRKeyRequest"
    PAYLOAD_TYPE = DRKeyType.REQUEST_KEY
    LEN = 00  # TODO(rsd) Set length usefully

    def __init__(self, raw=None):  # pragma: no cover
        """
        Initialize an instance of the class DRKeyRequestKey.

        :param raw:
        :type raw:
        """
        super().__init__()
        self.hop = 0
        self.session_id = []
        self.private_key = []
        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        data = Raw(raw, self.NAME, len(raw))
        self.hop = data.pop(1)
        self.session_id = data.pop(DRKeyConstants.SESSION_ID_BYTE_LENGTH)
        self.private_key = data.pop(DRKeyConstants.PRIVATE_KEY_BYTE_LENGTH)

    @classmethod
    def from_values(cls, hop, session_id, private_key):
        """
        Returns PathSegmentInfo with fields populated from values.
        :param hop: hop the packet is addressed to
        :type: int (PathSegmentType)
        :param session_id: session id
        :type session_id: int TODO replace
        :param private_key: private key
        :type private_key: byte array TODO replace
        """
        inst = cls()
        inst.hop = hop
        inst.session_id = session_id
        inst.private_key = private_key
        return inst

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.hop))
        packed.append(struct.pack())
        packed.append(ISD_AD(self.dst_isd, self.dst_ad).pack())
        return b"".join(packed)

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __str__(self):
        return "[%s(%dB): seg type:%s src isd/ad: %s/%s dst isd/ad: %s/%s]" % (
            self.NAME, len(self), PST.to_str(self.seg_type),
            self.src_isd, self.src_ad, self.dst_isd, self.dst_ad,
        )


class DRKeyResponseKey(object):
    pass


class DRKeySendKeys(object):
    pass


class DRKeyAcknowledgeKeys(object):
    pass


_TYPE_MAP = {
    DRKeyType.REQUEST_KEY: (DRKeyRequestKey, None),
    DRKeyType.REPLY_KEY: (DRKeyResponseKey, None),
    DRKeyType.SEND_KEYS: (DRKeySendKeys, None),
    DRKeyType.ACKNOWLEDGE_KEYS: (DRKeyAcknowledgeKeys, None),
}


def parse_pathmgmt_payload(type_, data):
    if type_ not in _TYPE_MAP:
        raise SCIONParseError("Unsupported path management type: %s", type_)
    handler, len_ = _TYPE_MAP[type_]
    return handler(data.pop(len_))


"""
Modified retroactive DRKey

-Assume long-term symetric key K_sd between source and destination
-F(k, v) is a pseudo-random function using key k.

Source S
-----------------------------------
1. Compute K_sdc = F(K_sd, FlowID)
//2. Compute AUTHc = AuthEncrypt()
2. Compute K_d = F(SV_s, FlowID)
3. for intermediate in Path:
		request Key from intermediate: {req, Pkd⁻¹}
		Ki = recv(request)
4. send Enc(K_sdc,{k1, ..., Kn, K_d}) to D
5. recv ack


Intermediate I
-----------------------------------
1. Compute K_i = F(SV_i, FlowID)
2. Encrypt and sign:
	K_ic = Enc(PKc, K_i);
	S_ic = Sign(PKi⁻¹, K_i||FlowID)
3. Send {K_ic, S_ic} to S

Destination D
-----------------------------------
1. Compute K_sdc = F(K_sd, FlowID)
2. Store Dec(K_sdc, message)
3. ack



Retroactive Pathtrace


Source S
-----------------------------------
1. Use K_d from mrDRKey
2. Compute DATAHASH = H(Payload)
3. Compute PVF = MAC(K_d, DATAHASH)
4. Put header {DATAHASH, FlowID, PVF}

(async)
5. Compute PVF' = MAC(K_d, DATAHASH)
			for i in Intermediate:
				PVF' = MAC(K_i, PVF')
	compare PVF == PVF'

Intermediate I
----------------------------------
1. Compute K_i = F(SV_i, FlowID)
2. Compute PVF = MAC(K_i, PVF)
3. Update header {DATAHASH, FlowID, PVF}

Destination D
----------------------------------
1. Store Header for later checking

(async)
2. To check:
	Compute PVF' = MAC(K_d, DATAHASH)
			for i in Intermediate:
				PVF' = MAC(K_i, PVF')
	compare PVF == PVF'
3. Send Enc(K_d, PVF||DATAHASH) to source



"""