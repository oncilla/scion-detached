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
:mod:`base_cli_srv` --- Base classes for single packet end2end testing
======================================================================
"""
# Stdlib
import argparse
import copy
import logging
import os
import random
import socket
import sys
import threading
import time
from abc import ABCMeta, abstractmethod
from itertools import product

# SCION
from endhost.sciond import SCIOND_API_SOCKDIR, SCIONDaemon
from lib.defines import AS_LIST_FILE, GEN_PATH, SCION_UDP_EH_DATA_PORT
from lib.log import init_logging
from lib.main import main_wrapper
from lib.packet.host_addr import (
    haddr_parse_interface,
)
from lib.packet.packet_base import PayloadRaw
from lib.packet.scion import SCIONL4Packet, build_base_hdrs
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.packet.scion_udp import SCIONUDPHeader
from lib.sciond_api.parse import parse_sciond_msg
from lib.sciond_api.path_req import (
    SCIONDPathReplyError,
    SCIONDPathRequest,
)
from lib.socket import ReliableSocket
from lib.thread import kill_self, thread_safety_net
from lib.types import SCIONDMsgType as SMT
from lib.util import (
    handle_signals,
    load_yaml_file,
)

API_TOUT = 15


class ResponseRV:
    FAILURE = 0
    SUCCESS = 1
    RETRY = 2


class TestBase(object, metaclass=ABCMeta):
    def __init__(self, sd, api_addr, data, finished, addr, timeout=1.0):
        self.sd = sd
        self.api_addr = api_addr
        self.data = data
        self.finished = finished
        self.addr = addr
        self._timeout = timeout
        self._api_socket = None
        self.sock = self._create_socket(addr)
        assert self.sock
        self.success = None

    @abstractmethod
    def run(self):
        raise NotImplementedError

    def api_socket(self):
        if not self._api_socket:
            self._api_socket = ReliableSocket()
            try:
                self._api_socket.connect(self.api_addr)
            except OSError as e:
                logging.critical("Error connecting to sciond: %s", e)
                kill_self()
        return self._api_socket

    def _create_socket(self, addr):
        sock = ReliableSocket(reg=(addr, 0, True, None))
        sock.settimeout(self._timeout)
        return sock

    def _recv(self):
        try:
            packet = self.sock.recv()[0]
        except socket.timeout:
            return None
        return SCIONL4Packet(packet)

    def _send_pkt(self, spkt, next_=None):
        next_hop, port = next_ or self.sd.get_first_hop(spkt)
        assert next_hop is not None
        logging.debug("Sending (via %s:%s):\n%s", next_hop, port, spkt)
        self.sock.send(spkt.pack(), (next_hop, port))

    def _shutdown(self):
        self.sock.close()
        if self._api_socket:
            self._api_socket.close()


class TestClientBase(TestBase):
    """
    Base client app
    """
    def __init__(self, sd, api_addr, data, finished, addr, dst, dport, api=True,
                 timeout=3.0, retries=0):
        self.dst = dst
        self.dport = dport
        self.api = api
        self.path_meta = None
        self.first_hop = None
        self.retries = retries
        self._req_id = 0
        super().__init__(sd, api_addr, data, finished, addr, timeout)
        self._get_path(api)

    def _get_path(self, api, flush=False):
        if api:
            self._get_path_via_api(flush)
        else:
            self._get_path_direct()
        assert self.path_meta.p.mtu

    def _get_path_via_api(self, flush=False):
        """Request path via SCIOND API."""
        response = self._try_sciond_api(flush)
        path_entry = response.path_entry(0)
        self.path_meta = path_entry.path()
        fh_addr = path_entry.ipv4()
        if not fh_addr:
            fh_addr = self.dst.host
        port = path_entry.p.port or SCION_UDP_EH_DATA_PORT
        self.first_hop = (fh_addr, port)

    def _try_sciond_api(self, flush=False):
        request = SCIONDPathRequest.from_values(
            self._req_id, self.dst.isd_as, flush=flush)
        packed = request.pack_full()
        self._req_id += 1
        start = time.time()
        while time.time() - start < API_TOUT:
            logging.debug("Sending path request to local API at %s: %s",
                          self.api_addr, request)
            self.api_socket().send(packed)
            data = self.api_socket().recv()[0]
            if data:
                response = parse_sciond_msg(data)
                if response.MSG_TYPE != SMT.PATH_REPLY:
                    logging.error("Unexpected SCIOND msg type received: %s" %
                                  response.NAME)
                    continue
                if response.p.errorCode != SCIONDPathReplyError.OK:
                    logging.error(
                        "SCIOND returned an error (code=%d): %s" %
                        (response.p.errorCode,
                         SCIONDPathReplyError.describe(response.p.errorCode)))
                    continue
                return response
            logging.debug("Empty response from local api.")
        logging.critical("Unable to get path from local api.")
        kill_self()

    def _get_path_direct(self, flags=0):
        """Request path from SCIOND object."""
        paths = []
        for _ in range(5):
            paths, _ = self.sd.get_paths(self.dst.isd_as, flags=flags)
            if paths:
                break
        else:
            logging.critical("Unable to get path directly from sciond")
            kill_self()
        self.path_meta = paths[0]
        self.first_hop = None

    def run(self):
        while not self.finished.is_set():
            self._send()
            start = time.time()
            spkt = self._recv()
            recv_dur = time.time() - start
            if not spkt:
                logging.info("Timeout waiting for response.")
                self._retry_or_stop(flush=True)
                continue
            r_code = self._handle_response(spkt)
            if r_code in [ResponseRV.FAILURE, ResponseRV.SUCCESS]:
                self._stop(success=bool(r_code))
            else:
                # Rate limit retries to 1 request per second.
                self._retry_or_stop(1.0 - recv_dur)
        self._shutdown()

    def _retry_or_stop(self, delay=0.0, flush=False):
        if delay < 0:
            delay = 0
        if self.retries:
            self.retries -= 1
            logging.info(
                "Retrying in %.1f s... (%d retries remaining, flush=%s)." %
                (delay, self.retries, flush))
            time.sleep(delay)
            self._get_path(self.api, flush=flush)
        else:
            self._stop()

    def _stop(self, success=False):
        self.success = success
        self.finished.set()

    def _send(self):
        self._send_pkt(self._build_pkt(), self.first_hop)
        if self.path_meta:
            logging.debug("Interfaces: %s", ", ".join(
                [str(ifentry) for ifentry in self.path_meta.iter_ifs()]))

    def _build_pkt(self, path=None):
        cmn_hdr, addr_hdr = build_base_hdrs(self.addr, self.dst)
        l4_hdr = self._create_l4_hdr()
        extensions = self._create_extensions()
        if path is None:
            path = self.path_meta.fwd_path()
        spkt = SCIONL4Packet.from_values(
            cmn_hdr, addr_hdr, path, extensions, l4_hdr)
        spkt.set_payload(self._create_payload(spkt))
        spkt.update()
        return spkt

    def _get_first_hop(self, spkt):
        return self.sd.get_first_hop(spkt)

    def _create_payload(self, spkt):
        return PayloadRaw(self.data)

    def _create_l4_hdr(self):
        return SCIONUDPHeader.from_values(
            self.addr, self.sock.port, self.dst, self.dport)

    def _create_extensions(self):
        return []

    @abstractmethod
    def _handle_response(self, spkt):
        raise NotImplementedError


class TestServerBase(TestBase):
    """
    Base server app
    """
    def run(self):
        while not self.finished.is_set():
            spkt = self._recv()
            if spkt and not self._handle_request(spkt):
                self.success = False
                self.finished.set()
        self._shutdown()

    @abstractmethod
    def _handle_request(self, spkt):
        raise NotImplementedError


class TestClientServerBase(object):
    """
    Test module to run client and server
    """
    NAME = ""

    def __init__(self, client, server, sources, destinations, local=True,
                 max_runs=None, retries=0):
        assert self.NAME
        t = threading.current_thread()
        t.name = self.NAME
        self.client_ip = haddr_parse_interface(client)
        self.server_ip = haddr_parse_interface(server)
        self.src_ias = sources
        self.dst_ias = destinations
        self.local = local
        self.scionds = {}
        self.max_runs = max_runs
        self.retries = retries

    def run(self):
        try:
            self._run()
        finally:
            self._stop_scionds()
        logging.info("All tests successful")

    def _run(self):
        """
        Run a test for every pair of src and dst
        """
        # Generate all possible pairs, and randomise the order.
        pairs = list(product(self.src_ias, self.dst_ias))
        random.shuffle(pairs)
        count = 0
        for src_ia, dst_ia in pairs:
            if not self.local and src_ia == dst_ia:
                continue
            count += 1
            if self.max_runs and count > self.max_runs:
                logging.debug("Hit max runs (%d), stopping", self.max_runs)
                break
            src = SCIONAddr.from_values(src_ia, self.client_ip)
            dst = SCIONAddr.from_values(dst_ia, self.server_ip)
            t = threading.current_thread()
            t.name = "%s %s > %s main" % (self.NAME, src_ia, dst_ia)
            if not self._run_test(src, dst):
                sys.exit(1)

    def _run_test(self, src, dst):
        """
        Run client and server, wait for both to finish
        """
        logging.info("Testing: %s -> %s", src.isd_as, dst.isd_as)
        # finished is used by the client/server to signal to the other that they
        # are stopping.
        finished = threading.Event()
        data = self._create_data(src, dst)
        server = self._create_server(data, finished, dst)
        client = self._create_client(data, finished, src, dst, server.sock.port)
        server_name = "%s %s > %s server" % (self.NAME, src.isd_as, dst.isd_as)
        s_thread = threading.Thread(
            target=thread_safety_net, args=(server.run,), name=server_name,
            daemon=True)
        s_thread.start()
        client.run()
        # If client is finished, server should finish within ~1s (due to recv
        # timeout). If it hasn't, then there was a problem.
        s_thread.join(5.0)
        if s_thread.is_alive():
            logging.error("Timeout waiting for server thread to terminate")
            return False
        return self._check_result(client, server)

    def _check_result(self, client, server):
        if client.success and server.success:
            logging.debug("Success")
            return True
        logging.error("Client success? %s Server success? %s",
                      client.success, server.success)
        return False

    def _create_data(self, src, dst):
        return ("%s <-> %s" % (src.isd_as, dst.isd_as)).encode("UTF-8")

    def _create_server(self, data, finished, addr):
        """
        Instantiate server app
        """
        sd, api_addr = self._run_sciond(addr)
        return TestServerBase(sd, api_addr, data, finished, addr)

    def _create_client(self, data, finished, src, dst, port):
        """
        Instantiate client app
        """
        sd, api_addr = self._run_sciond(src)
        return TestClientBase(sd, api_addr, data, finished, src, dst,
                              port, retries=self.retries)

    def _run_sciond(self, addr):
        api_addr = SCIOND_API_SOCKDIR + "%s_%s.sock" % (
                self.NAME, addr.isd_as)
        if addr.isd_as not in self.scionds:
            logging.debug("Starting sciond for %s", addr.isd_as)
            # Local api on, random port, random api port
            self.scionds[addr.isd_as] = start_sciond(
                addr, api=True, api_addr=api_addr)
        return self.scionds[addr.isd_as], api_addr

    def _stop_scionds(self):
        for sd in self.scionds.values():
            sd.stop()


def start_sciond(addr, api=False, port=0, api_addr=None):
    conf_dir = "%s/ISD%d/AS%d/endhost" % (
        GEN_PATH, addr.isd_as[0], addr.isd_as[1])
    return SCIONDaemon.start(
        conf_dir, addr.host, api_addr=api_addr, run_local_api=api, port=port)


def _load_as_list():
    as_dict = load_yaml_file(os.path.join(GEN_PATH, AS_LIST_FILE))
    as_list = []
    for as_str in as_dict.get("Non-core", []) + as_dict.get("Core", []):
        as_list.append(ISD_AS(as_str))
    return as_list


def _parse_locs(as_str, as_list):
    if as_str:
        return [ISD_AS(as_str)]
    copied = copy.copy(as_list)
    random.shuffle(copied)
    return copied


def setup_main(name, parser=None):
    handle_signals()
    parser = parser or argparse.ArgumentParser()
    parser.add_argument('-l', '--loglevel', default="INFO",
                        help='Console logging level (Default: %(default)s)')
    parser.add_argument('-c', '--client', help='Client address')
    parser.add_argument('-s', '--server', help='Server address')
    parser.add_argument('-m', '--mininet', action='store_true',
                        help="Running under mininet")
    parser.add_argument("-r", "--runs", type=int,
                        help="Limit the number of pairs tested")
    parser.add_argument("-w", "--wait", type=float, default=0.0,
                        help="Time in seconds to wait before running")
    parser.add_argument("--retries", type=int, default=0,
                        help="Number of retries before giving up.")
    parser.add_argument('src_ia', nargs='?', help='Src isd-as')
    parser.add_argument('dst_ia', nargs='?', help='Dst isd-as')
    args = parser.parse_args()
    init_logging("logs/%s" % name, console_level=args.loglevel)

    if not args.client:
        args.client = "169.254.0.2" if args.mininet else "127.0.0.2"
    if not args.server:
        args.server = "169.254.0.3" if args.mininet else "127.0.0.3"
    as_list = _load_as_list()
    srcs = _parse_locs(args.src_ia, as_list)
    dsts = _parse_locs(args.dst_ia, as_list)
    return args, srcs, dsts


def main():
    args, srcs, dsts = setup_main("base")
    TestClientServerBase(args.client, args.server, srcs, dsts).run()


if __name__ == "__main__":
    main_wrapper(main)
