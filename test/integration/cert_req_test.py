#!/usr/bin/python3
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
:mod:`cert_req_est` --- SCION certificate request tests
=======================================================
"""

# Stdlib
import logging
import sys
import threading

# SCION
from lib.defines import CERTIFICATE_SERVICE
from lib.main import main_wrapper
from lib.packet.cert_mgmt import CertChainRequest, TRCRequest
from lib.packet.path import SCIONPath
from lib.packet.scion import SCIONL4Packet, build_base_hdrs
from lib.packet.scion_addr import SCIONAddr
from test.integration.base_cli_srv import (
    setup_main,
    TestClientBase,
    TestClientServerBase,
)


class TestCertClient(TestClientBase):
    def __init__(self, sd, api_addr, finished, addr):
        cs = sd.dns_query_topo(CERTIFICATE_SERVICE)[0]
        cs_addr = SCIONAddr.from_values(addr.isd_as, cs[0])
        self.cert_done = False
        super().__init__(sd, api_addr, "", finished, addr, cs_addr, cs[1])

    def _get_path(self, api):
        pass  # No path required. All queries go to local CS

    def _build_pkt(self):
        cmn_hdr, addr_hdr = build_base_hdrs(self.addr, self.dst)
        l4_hdr = self._create_l4_hdr()
        spkt = SCIONL4Packet.from_values(
            cmn_hdr, addr_hdr, SCIONPath(), [], l4_hdr)
        spkt.set_payload(self._create_payload(spkt))
        spkt.update()
        return spkt

    def _create_payload(self, _):
        if not self.cert_done:
            return CertChainRequest.from_values(self.addr.isd_as, 0)
        return TRCRequest.from_values(self.addr.isd_as, 0)

    def _handle_response(self, spkt):
        pld = spkt.parse_payload()
        logging.debug("Got:\n%s", spkt)
        if not self.cert_done:
            if (self.addr.isd_as, 0 == pld.chain.get_leaf_isd_as_ver()):
                logging.debug("Cert query success")
                self.cert_done = True
                return True
            logging.error("Cert query failed")
            return False
        if (self.addr.isd_as[0], 0 == pld.trc.get_isd_ver()):
            logging.debug("TRC query success")
            self.success = True
            self.finished.set()
            return True
        logging.error("TRC query failed")
        return False


class TestCertReq(TestClientServerBase):
    NAME = "CertReqTest"

    def _run(self):
        for isd_as in self.src_ias:
            if not self._run_test(isd_as):
                sys.exit(1)

    def _run_test(self, isd_as):
        logging.info("Testing: %s", isd_as)
        finished = threading.Event()
        addr = SCIONAddr.from_values(isd_as, self.client_ip)
        client = self._create_client(finished, addr)
        client.run()
        if client.success:
            return True
        logging.error("Client success? %s", client.success)
        return False

    def _create_client(self, finished, addr):
        sd, api_addr = self._run_sciond(addr)
        return TestCertClient(sd, api_addr, finished, addr)


def main():
    args, srcs, dsts = setup_main("certreq")
    TestCertReq(args.client, args.server, srcs, dsts, max_runs=args.runs).run()


if __name__ == "__main__":
    main_wrapper(main)
