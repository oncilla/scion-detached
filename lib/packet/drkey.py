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
import logging
import struct
from collections import defaultdict

# Crypto
from nacl.public import PublicKey

# SCION
from lib.crypto.certificate import CertificateChain
from lib.types import DRKeyType as DRKT
from lib.errors import SCIONParseError
from lib.packet.packet_base import DRKeyPayloadBase
from lib.util import Raw


class DRKeyConstants(object):
    """
    Constants for drkey.
    """
    SESSION_ID_BYTE_LENGTH = 16


class DRKeyRequestKey(DRKeyPayloadBase):
    """
    DRKeyRequestKey class used in sending DRKey requests.
    """
    NAME = "DRKeyRequest"
    PAYLOAD_TYPE = DRKT.REQUEST_KEY

    def __init__(self, raw=None):  # pragma: no cover
        """
        Initialize an instance of the class DRKeyRequestKey.

        :param raw:
        :type raw: bytes
        """
        super().__init__()
        self.hop = 0
        # self.cc_length = None
        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        data = Raw(raw, self.NAME, len(raw))
        self.hop = data.pop(1)
        self.session_id = data.pop(DRKeyConstants.SESSION_ID_BYTE_LENGTH)
        self.public_key_length = data.pop(1)
        self.public_key = data.pop(self.public_key_length)
        # self.cc_length = int.from_bytes(data.pop(4), byteorder='big', signed=False)
        # self.certificate_chain = CertificateChain.parse(data.pop(self.cc_length).decode("UTF-8"))

    @classmethod
    def from_values(cls, hop, session_id, public_key):
        """
        Returns DRKeyRequestKey with fields populated from values.

        :param hop: hop on path the packet is addressed to
        :type: int
        :param session_id: session id of the flow (16 B)
        :type session_id: bytes
        :param public_key: public key of the source
        :type public_key: bytes
        """
        inst = cls()
        inst.hop = hop
        inst.session_id = session_id
        inst.public_key = public_key
        # inst.certificate_chain = certificate_chain
        return inst

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.hop))
        packed.append(self.session_id)
        packed.append(struct.pack("!B", len(self.public_key)))
        packed.append(self.public_key)
        # certificate_chain = self.certificate_chain.pack()
        # self.cc_length = len(certificate_chain)
        # packed.append(struct.pack("!I", self.cc_length))
        # packed.append(certificate_chain)
        return b"".join(packed)

    def __len__(self):  # pragma: no cover
        return 1 + DRKeyConstants.SESSION_ID_BYTE_LENGTH + 1 + len(self.public_key)  # 4 + self.cc_length

    def __str__(self):
        return "[%s(%dB): hop:%d SessionID: %s PublicKey: %s]" % (
            self.NAME, len(self), self.hop, str(self.session_id), str(self.public_key)
        )


class DRKeyReplyKey(DRKeyPayloadBase):
    """
    DRKeyReplyKey class used in answering DRKey requests.
    """
    NAME = "DRKeyReply"
    PAYLOAD_TYPE = DRKT.REPLY_KEY

    def __init__(self, raw=None):  # pragma: no cover
        """
        Initialize an instance of the class DRKeyRequestKey.

        :param raw:
        :type raw: bytes
        """
        super().__init__()
        self.hop = 0
        self.session_id = None
        self.enc_key_length = None
        self.encrypted_session_key = None
        self.sign_length = None
        self.signature = None  # signature for encrypted session key || session id
        self.cc_length = None
        self.certificate_chain = None
        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        data = Raw(raw, self.NAME, len(raw))
        self.hop = data.pop(1)
        self.session_id = data.pop(DRKeyConstants.SESSION_ID_BYTE_LENGTH)
        self.enc_key_length = int.from_bytes(data.pop(2), byteorder='big', signed=False)
        self.encrypted_session_key = data.pop(self.enc_key_length)
        self.sign_length = int.from_bytes(data.pop(2), byteorder='big', signed=False)
        self.signature = data.pop(self.sign_length)
        self.cc_length = int.from_bytes(data.pop(4), byteorder='big', signed=False)
        if self.cc_length > 0:
            self.certificate_chain = CertificateChain(data.pop(self.cc_length).decode("UTF-8"))

    @classmethod
    def from_values(cls, hop, session_id, encrypted_session_key, signature, certificate_chain):
        """
        Returns PathSegmentInfo with fields populated from values.

        :param hop: hop the packet is addressed to
        :type hop: int (PathSegmentType)
        :param session_id: session id of the flow (16 B)
        :type session_id: bytes
        :param encrypted_session_key: encrypted session key
        :type encrypted_session_key: bytes
        :param signature: signature of concatenated {encrypted_session_key, session_id}
        :type signature: bytes
        :param certificate_chain: certificate chain of the AS at hop
        :type certificate_chain: CertificateChain
        """
        inst = cls()
        inst.hop = hop
        inst.session_id = session_id
        inst.signature = signature
        inst.encrypted_session_key = encrypted_session_key
        inst.certificate_chain = certificate_chain
        return inst

    def pack(self):
        self.enc_key_length = len(self.encrypted_session_key)
        self.sign_length = len(self.signature)

        if self.certificate_chain:
            certificate_chain = self.certificate_chain.pack()
            self.cc_length = len(certificate_chain)
        else:
            certificate_chain = None
            self.cc_length = 0

        packed = []
        packed.append(struct.pack("!B", self.hop))
        packed.append(self.session_id)
        packed.append(struct.pack("!H", self.enc_key_length))
        packed.append(self.encrypted_session_key)
        packed.append(struct.pack("!H", self.sign_length))
        packed.append(self.signature)
        packed.append(struct.pack("!I", self.cc_length))
        if certificate_chain:
            packed.append(certificate_chain)
        return b"".join(packed)

    def __len__(self):  # pragma: no cover
        if not self.enc_key_length:
            self.enc_key_length = len(self.encrypted_session_key)
        if not self.sign_length:
            self.sign_length = len(self.signature)
        if not self.cc_length:
            if self.certificate_chain:
                self.cc_length = len(self.certificate_chain.pack())
            else:
                self.cc_length = 0
        return 1 + 16 + 2 + self.enc_key_length + 2 + self.sign_length + 4 + self.cc_length

    def __str__(self):
        return "[%s(%dB): hop:%d EncSessionKey: %s Signature: %s]" % (
            self.NAME, len(self), self.hop, str(self.encrypted_session_key), str(self.signature)
        )


class DRKeySendKeys(DRKeyPayloadBase):
    """
    DRKeySendKeys class used in sending DRKeys to the destination.

    # TODO support encrypted keys
    """
    NAME = "DRKeySendKeys"
    PAYLOAD_TYPE = DRKT.SEND_KEYS

    def __init__(self, raw=None):  # pragma: no cover
        """
        Initialize an instance of the class DRKeyRequestKey.

        :param raw:
        :type raw: bytes
        """
        super().__init__()
        self.session_id = None
        self.keys_length = None
        self.keys = None
        self.cc_length = None
        self.certificate_chain = None
        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        data = Raw(raw, self.NAME, len(raw))
        self.session_id = data.pop(DRKeyConstants.SESSION_ID_BYTE_LENGTH)
        self.keys_length = int.from_bytes(data.pop(2), byteorder='big', signed=False)
        self.keys = []
        for _ in range(self.keys_length):
            self.keys.append(data.pop(DRKeyConstants.SESSION_ID_BYTE_LENGTH))
        self.cc_length = int.from_bytes(data.pop(4), byteorder='big', signed=False)
        if self.cc_length > 0:
            self.certificate_chain = CertificateChain(data.pop(self.cc_length).decode("UTF-8"))

    @classmethod
    def from_values(cls, session_id, keys, certificate_chain):
        """
        Returns PathSegmentInfo with fields populated from values.

        :param session_id: session id from flow (16 B)
        :type session_id: bytes
        :param keys: encrypted blob of concatenated [session_key_1, ..., session_key_n]
        :type keys: [bytes]
        :param certificate_chain: certificate chain of the source
        :type certificate_chain: CertificateChain
        """
        inst = cls()
        inst.session_id = session_id
        inst.keys = keys
        inst.certificate_chain = certificate_chain
        return inst

    def pack(self):
        self.keys_length = len(self.keys)

        if self.certificate_chain:
            certificate_chain = self.certificate_chain.pack()
            self.cc_length = len(certificate_chain)
        else:
            certificate_chain = None
            self.cc_length = 0

        packed = []
        packed.append(self.session_id)
        packed.append(struct.pack("!H", self.keys_length))
        for key in self.keys:
            packed.append(key)
        packed.append(struct.pack("!I", self.cc_length))
        if certificate_chain:
            packed.append(certificate_chain)
        return b"".join(packed)

    def __len__(self):  # pragma: no cover
        if not self.keys_length:
            self.keys_length = len(self.keys)
        if not self.cc_length:
            if self.certificate_chain:
                self.cc_length = len(self.certificate_chain.pack())
            else:
                self.cc_length = 0
        return DRKeyConstants.SESSION_ID_BYTE_LENGTH + \
            2 + self.keys_length * DRKeyConstants.SESSION_ID_BYTE_LENGTH + 4 + self.cc_length

    def __str__(self):
        return "[%s(%dB): Keys: %s]" % (
            self.NAME, len(self), str(self.keys)
        )


class DRKeyAcknowledgeKeys(DRKeyPayloadBase):
    """
    DRKeyAcknowledgeKeys class used in acknowledging DRKeys to the destination.
    """
    NAME = "DRKeyAcknowledgeKeys"
    PAYLOAD_TYPE = DRKT.ACKNOWLEDGE_KEYS

    def __init__(self, raw=None):  # pragma: no cover
        """
        Initialize an instance of the class DRKeyRequestKey.

        :param raw:
        :type raw: bytes
        """
        super().__init__()
        self.session_id = None
        self.sign_length = None
        self.signature = None
        # self.cc_length = None
        # self.certificate_chain = None
        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        data = Raw(raw, self.NAME, len(raw))
        self.session_id = data.pop(DRKeyConstants.SESSION_ID_BYTE_LENGTH)
        self.sign_length = int.from_bytes(data.pop(2), byteorder='big', signed=False)
        self.signature = data.pop(self.sign_length)
        # self.cc_length = int.from_bytes(data.pop(4), byteorder='big', signed=False)
        # self.certificate_chain = CertificateChain(data.pop(self.cc_length).decode("UTF-8"))

    @classmethod
    def from_values(cls, session_id, signature):
        """
        Returns PathSegmentInfo with fields populated from values.
        :param session_id: session id of the flow (16 B)
        :type session_id: bytes
        :param signature: signature
        :type signature: bytes
        """
        inst = cls()
        inst.session_id = session_id
        inst.signature = signature
        # inst.certificate_chain = certificate_chain
        return inst

    def pack(self):
        self.sign_length = len(self.signature)
        # certificate_chain = self.certificate_chain.pack()
        # self.cc_length = len(certificate_chain)
        packed = []
        packed.append(self.session_id)
        packed.append(struct.pack("!H", self.sign_length))
        packed.append(self.signature)
        # packed.append(struct.pack("!I", self.cc_length))
        # packed.append(certificate_chain)
        return b"".join(packed)

    def __len__(self):  # pragma: no cover
        if not self.sign_length:
            self.sign_length = len(self.signature)
        # if not self.cc_length:
        #    self.cc_length = len(self.certificate_chain.pack())
        return 16 + 2 + self.sign_length  # + 4 + self.cc_length

    def __str__(self):
        return "[%s(%dB): Signature: %s]" % (
            self.NAME, len(self), str(self.signature)
            # , str(self.certificate_chain)
        )


_TYPE_MAP = {
    DRKT.REQUEST_KEY: (DRKeyRequestKey, None),
    DRKT.REPLY_KEY: (DRKeyReplyKey, None),
    DRKT.SEND_KEYS: (DRKeySendKeys, None),
    DRKT.ACKNOWLEDGE_KEYS: (DRKeyAcknowledgeKeys, None),
}


def parse_drkey_payload(type_, data):
    if type_ not in _TYPE_MAP:
        raise SCIONParseError("Unsupported drkey type: %s", type_)
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
4. send Enc(K_sdc,{SessionID,k1, ..., Kn, K_d}) to D
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