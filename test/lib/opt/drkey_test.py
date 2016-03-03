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
:mod:`lib_packet_drkey_test` --- lib.packet.drkey tests
=====================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.errors import SCIONParseError
from lib.opt.drkey import (
    DRKeyRequestKey,
    DRKeyReplyKey,
    DRKeySendKeys,
    DRKeyAcknowledgeKeys,
    parse_drkey_payload,
    DRKeyConstants)
from test.testcommon import (
    create_mock,
)


class TestDRKeyRequestKey(object):
    """
    Unit tests for lib.packet.drkey.DRKeyRequestKey
    """

    @patch("lib.packet.drkey.Raw", autospec=True)
    def test_parse(self, raw):
        """
        Unit tests for lib.packet.drkey.DRKeyRequestKey._parse
        """

        data = create_mock(["pop"])
        data.pop.side_effect = "hop", "session_id", 0x10, "key"
        raw.return_value = data

        inst = DRKeyRequestKey()
        inst._parse("data")
        ntools.assert_true(raw.call_count == 1)
        ntools.eq_(inst.hop, "hop")
        ntools.eq_(inst.session_id, "session_id")
        ntools.eq_(inst.public_key_length, 16)
        ntools.eq_(inst.public_key, "key")
        data.pop.assert_any_call(16)

    def test_pack(self):
        """
        Unit tests for lib.packets.drkey.DRKeyRequestKey.pack
        """
        session_id = bytes.fromhex("00112233445566778899aabbccddeeff")
        key = bytes.fromhex("ffeeddccbbaa99887766554433221100")

        inst = DRKeyRequestKey()
        inst.hop = 0x3
        inst.session_id = session_id
        inst.public_key_length = len(key)
        inst.public_key = key

        expected = b"".join([bytes([0x3]), session_id, bytes([len(key)]), key])

        ntools.eq_(inst.pack(), expected)

    def test_len(self):
        """
        Unit tests for lib.packet.drkey.DRKeyRequestKey.__len__
        """
        inst = DRKeyRequestKey()
        inst.public_key = [1,2,3,4,5,6,7,8]
        # Call
        ntools.eq_(len(inst), 1 + 16 + 1 + 8)


class TestDRKeyReplyKey(object):
    """
    Unit tests for lib.packet.drkey.DRKeyRequestKey
    """
    @patch("lib.packet.drkey.CertificateChain")
    @patch("lib.packet.drkey.Raw", autospec=True)
    def test_parse(self, raw, cert_chain):
        """
        Unit tests for lib.packet.drkey.DRKeyReplyKey._parse
        """

        data = create_mock(["pop"])
        data.pop.side_effect = (b"hop",
                                b"session_id",
                                bytes([0x00, 0x01]),
                                b"encrypted key",
                                bytes([0x00, 0x02]),
                                b"signature",
                                bytes([0x00, 0x03]),
                                b"certificate chain"
                                )
        raw.return_value = data
        cert_chain.side_effect = lambda x: x

        inst = DRKeyReplyKey()
        inst._parse("data")
        ntools.assert_true(raw.call_count == 1)
        data.pop.assert_any_call(1)
        data.pop.assert_any_call(2)
        data.pop.assert_any_call(3)
        ntools.eq_(inst.hop, b"hop")
        ntools.eq_(inst.session_id, b"session_id")
        ntools.eq_(inst.enc_key_length, 1)
        ntools.eq_(inst.cipher, b"encrypted key")
        ntools.eq_(inst.sign_length, 2)
        ntools.eq_(inst.signature, b"signature")
        ntools.eq_(inst.cc_length, 3)
        ntools.eq_(inst.certificate_chain, "certificate chain")

    def test_pack(self):
        """
        Unit tests for lib.packets.drkey.DRKeyReplyKey.pack
        """
        hop = 0x12
        session_id = bytes.fromhex("00112233445566778899aabbccddeeff")
        enc_key = bytes.fromhex("ffeeddccbbaa99887766554433221100")
        signature = b"hello I'm dog"
        certificate_chain = b"I took an arrow in the knee"

        inst = DRKeyReplyKey.from_values(hop, session_id, enc_key, signature, create_mock(["pack"]))
        inst.certificate_chain.pack.return_value = certificate_chain
        expected = b"".join([bytes([hop]),
                             session_id,
                             bytes([0x00, 0x10]),
                             enc_key,
                             bytes([0x00, 0x0d]),
                             signature,
                             bytes([0x00, 0x00, 0x00, 0x1b]),
                             certificate_chain
                             ])

        ntools.eq_(inst.pack(), expected)

    def test_len(self):
        """
        Unit tests for lib.packet.drkey.DRKeyReplyKey.__len__
        """
        hop = 0x12
        session_id = bytes.fromhex("00112233445566778899aabbccddeeff")
        enc_key = bytes.fromhex("ffeeddccbbaa99887766554433221100")
        signature = b"hello I'm dog"
        certificate_chain = b"I took an arrow in the knee"

        inst = DRKeyReplyKey.from_values(hop, session_id, enc_key, signature, create_mock(["pack"]))
        inst.certificate_chain.pack.return_value = certificate_chain

        ntools.eq_(len(inst), 1 + 16 + 2 + len(enc_key) + 2 + len(signature) + 4 + len(certificate_chain))


class TestDRKeySendKeys(object):
    """
    Unit tests for lib.packet.drkey.DRKeySendKeys
    """
    @patch("lib.packet.drkey.Raw", autospec=True)
    def test_parse(self, raw):
        """
        Unit tests for lib.packet.drkey.DRKeySendKeys._parse
        """

        data = create_mock(["pop"])
        data.pop.side_effect = (b"session_id",
                                bytes([0x00, 0x02]),
                                b"key1",
                                b"key2",
                                )
        raw.return_value = data

        inst = DRKeySendKeys()
        inst._parse("data")
        ntools.assert_true(raw.call_count == 1)
        ntools.eq_(inst.session_id, b"session_id")
        ntools.eq_(inst.keys_length, 2)
        ntools.eq_(inst.keys, [b"key1", b"key2"])

    def test_pack(self):
        """
        Unit tests for lib.packets.drkey.DRKeySendKeys.pack
        """
        session_id = bytes.fromhex("00112233445566778899aabbccddeeff")

        inst = DRKeySendKeys.from_values(session_id, [b"key1", b"key2"])
        expected = b"".join([session_id,
                             bytes([0x00, 0x02]),
                             b"key1",
                             b"key2",
                             ])

        ntools.eq_(inst.pack(), expected)

    def test_len(self):
        """
        Unit tests for lib.packet.drkey.DRKeySendKeys.__len__
        """

        session_id = bytes.fromhex("00112233445566778899aabbccddeeff")

        inst = DRKeySendKeys.from_values(session_id, [b"key1", b"key2"])

        ntools.eq_(len(inst), 16 + 2 + 2 * DRKeyConstants.DRKEY_BYTE_LENGTH)


class DRKeyAcknowledgeKeys(object):
    """
    Unit tests for lib.packet.drkey.DRKeyAcknowledgeKeys
    """
    @patch("lib.packet.drkey.Raw", autospec=True)
    def test_parse(self, raw):
        """
        Unit tests for lib.packet.drkey.DRKeyAcknowledgeKeys._parse
        """

        data = create_mock(["pop"])
        data.pop.side_effect = (b"session_id",
                                b"src key",
                                bytes([0x00, 0x02]),
                                b"signature",
                                )
        raw.return_value = data

        inst = DRKeyAcknowledgeKeys()
        inst._parse("data")
        ntools.assert_true(raw.call_count == 1)
        ntools.eq_(inst.session_id, b"session_id")
        ntools.eq_(inst.src_key, b"src key")
        ntools.eq_(inst.sign_length, 2)
        ntools.eq_(inst.signature, b"signature")

    def test_pack(self):
        """
        Unit tests for lib.packets.drkey.DRKeyAcknowledgeKeys.pack
        """
        session_id = bytes.fromhex("00112233445566778899aabbccddeeff")

        inst = DRKeyAcknowledgeKeys.from_values(session_id, b"src key", b"signature")
        expected = b"".join([session_id,
                             b"src key",
                             bytes([0x00, 0x09]),
                             b"signature",
                             ])

        ntools.eq_(inst.pack(), expected)

    def test_len(self):
        """
        Unit tests for lib.packet.drkey.DRKeyAcknowledgeKeys.__len__
        """

        session_id = bytes.fromhex("00112233445566778899aabbccddeeff")

        inst = DRKeyAcknowledgeKeys.from_values(session_id, b"key", b"signature")

        ntools.eq_(len(inst), 16 + 16 + 2 + len(b"signature"))


class TestParseDRKeyPayload(object):
    """
    Unit tests for lib.packet.drkey.parse_drkey_payload
    """
    @patch("lib.packet.drkey._TYPE_MAP", new_callable=dict)
    def _check_supported(self, type_, type_map):
        type_map[0] = create_mock(), 20
        type_map[1] = create_mock(), None
        handler, len_ = type_map[type_]
        data = create_mock(["pop"])
        # Call
        ntools.eq_(parse_drkey_payload(type_, data), handler.return_value)
        # Tests
        data.pop.assert_called_once_with(len_)
        handler.assert_called_once_with(data.pop.return_value)

    def test_supported(self):
        for type_ in (0, 1):
            yield self._check_supported, type_

    def test_unsupported(self):
        # Call
        ntools.assert_raises(SCIONParseError, parse_drkey_payload,
                             "unknown type", "data")


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
