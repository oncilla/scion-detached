#!/usr/bin/python3
# Copyright 2014 ETH Zurich
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
:mod:`end2end_test` --- SCION end2end tests
===========================================
"""
# Stdlib
import argparse
import copy
import logging
import os
import random
import struct
import sys
import threading
import time
import unittest

# PyNaCl
from nacl.utils import random as rand_nonce

# SCION
from endhost.sciond import SCIOND_API_HOST, SCIOND_API_PORT, SCIONDaemon
from lib.defines import AD_LIST_FILE, GEN_PATH
from lib.log import init_logging
from lib.main import main_wrapper
from lib.packet.host_addr import (
    haddr_get_type,
    haddr_parse,
    haddr_parse_interface,
)
from lib.packet.opaque_field import InfoOpaqueField
from lib.packet.packet_base import PayloadRaw
from lib.packet.path import CorePath, CrossOverPath, EmptyPath, PeerPath
from lib.packet.scion import SCIONL4Packet, build_base_hdrs
from lib.packet.scion_addr import SCIONAddr, ISD_AD
from lib.packet.scion_udp import SCIONUDPHeader
from lib.socket import UDPSocket
from lib.thread import kill_self, thread_safety_net
from lib.types import AddrType, OpaqueFieldType as OFT
from lib.util import Raw, handle_signals, load_yaml_file

TOUT = 10  # How long wait for response.

class Ping(object):
    """
    Simple ping app.
    """
    def __init__(self, src, dst, dport, token, session_id):
        self.src = src
        self.dst = dst
        self.dport = dport
        self.token = token
        self.pong_received = False
        conf_dir = "%s/ISD%d/AD%d/endhost" % (GEN_PATH, src.isd_id, src.ad_id)
        # Local api on, random port:
        self.sd = SCIONDaemon.start(
            conf_dir, self.src.host_addr, run_local_api=True, port=0)
        # self.get_path()
        self.path = self.sd.get_paths(self.dst.isd_id, self.dst.ad_id)[0]
        self.sock = UDPSocket(bind=(str(self.src.host_addr), 0, "Ping App"),
                              addr_type=AddrType.IPV4)
        self.session_id = session_id
        self.keys = None

    def run(self):
        self.send()
        self.recv()

    def send(self):

        self.sd.get_drkey_destination(self.session_id)
        self.sd.get_drkeys(self.dst, self.path, self.session_id, non_blocking=True)

        cmn_hdr, addr_hdr = build_base_hdrs(self.src, self.dst)
        payload = PayloadRaw(b"ping " + self.token)
        udp_hdr = SCIONUDPHeader.from_values(
            self.src, self.sock.port, self.dst, self.dport, payload)
        spkt = SCIONL4Packet.from_values(
            cmn_hdr, addr_hdr, self.path, [], udp_hdr, payload)
        (next_hop, port) = self.sd.get_first_hop(spkt)
        self.sd.send(spkt, next_hop, port)

        logging.debug("Start to get keys (blocking)")
        self.keys = self.sd.get_drkeys(self.dst, self.path, self.session_id)
        self.sd.send_drkeys(self.dst, self.path, self.session_id)
        logging.debug("Sent keys %s", self.keys)

    def recv(self):
        packet = self.sock.recv()[0]
        spkt = SCIONL4Packet(packet)
        payload = spkt.get_payload()
        pong = PayloadRaw(b"pong " + self.token)
        if payload == pong:
            logging.info('%s:%d: pong received.', self.src.host_addr,
                         self.sock.port)
            self.pong_received = True
        else:
            logging.error("Unexpected payload received: %s (expected: %s)",
                          payload, pong)
            kill_self()
        self.sock.close()
        self.sd.stop()


class Pong(object):
    """
    Simple pong app.
    """
    def __init__(self, dst, token, session_id):
        self.dst = dst
        self.token = token
        self.ping_received = False
        self.keys = None
        self.session_id = session_id
        conf_dir = "%s/ISD%d/AD%d/endhost" % (
            GEN_PATH, self.dst.isd_id, self.dst.ad_id)
        # API off, standard port.
        self.sd = SCIONDaemon.start(conf_dir, self.dst.host_addr)
        self.sock = UDPSocket(bind=(str(self.dst.host_addr), 0, "Pong App"),
                              addr_type=AddrType.IPV4)

    def run(self):
        packet = self.sock.recv()[0]
        spkt = SCIONL4Packet(packet)
        payload = spkt.get_payload()
        ping = PayloadRaw(b"ping " + self.token)
        if payload == ping:
            # Reverse the packet and send "pong".
            logging.info('%s:%d: ping received, sending pong.',
                         self.dst.host_addr, self.sock.port)
            self.ping_received = True
            spkt.reverse()
            spkt.set_payload(PayloadRaw(b"pong " + self.token))
            logging.info("Replying with:\n%s", spkt)
            (next_hop, port) = self.sd.get_first_hop(spkt)
            assert next_hop is not None
            self.sd.send(spkt, next_hop, port)

        while not self.sd.get_drkeys(self.session_id):
            time.sleep(0.001)
            self.keys = self.sd.get_drkeys_remote(self.session_id)

        self.sock.close()
        self.sd.stop()


class TestSCIONDaemon(unittest.TestCase):
    """
    Unit tests for sciond.py. For this test a infrastructure must be running.
    """

    def test(self, client, server, sources, destinations):
        """
        Testing function. Creates an instance of SCIONDaemon, then verifies path
        requesting, and finally sends packet through SCION. Sender is placed in
        every AD from `sources`, and receiver is from every AD from
        `destinations`.
        """

        thread = threading.current_thread()
        thread.name = "E2E.MainThread"
        client_ip = haddr_parse_interface(client)
        server_ip = haddr_parse_interface(server)
        failures = 0
        for src_id in [sources[0]]:
            for dst_id in [destinations[0]]:
                logging.info("Testing: %s -> %s", src_id, dst_id)
                src = SCIONAddr.from_values(src_id[0], src_id[1], client_ip)
                dst = SCIONAddr.from_values(dst_id[0], dst_id[1], server_ip)
                token = (
                    "%s-%s<->%s-%s" % (src.isd_id, src.ad_id, dst.isd_id,
                                       dst.ad_id)
                ).encode("UTF-8")
                session_id = rand_nonce(16)
                pong_app = Pong(dst, token, session_id)
                threading.Thread(
                    target=thread_safety_net, args=(pong_app.run,),
                    name="E2E.pong_app", daemon=True).start()
                ping_app = Ping(src, dst, pong_app.sock.port, token, session_id)
                threading.Thread(
                    target=thread_safety_net, args=(ping_app.run,),
                    name="E2E.ping_app", daemon=True).start()
                for _ in range(TOUT * 10):
                    time.sleep(0.1)
                    if pong_app.ping_received and ping_app.pong_received:
                        break
                else:
                    logging.error("Test timed out")
                    failures += 1
                self.assertTrue(pong_app.ping_received)
                self.assertTrue(ping_app.pong_received)
                self.assertEqual(ping_app.keys, pong_app.keys)
        sys.exit(failures)


def _load_ad_list():
    ad_dict = load_yaml_file(os.path.join(GEN_PATH, AD_LIST_FILE))
    ad_list = []
    for ad_str in ad_dict.get("Non-core", []) + ad_dict.get("Core", []):
        isd, ad = ad_str.split("-")
        ad_list.append((int(isd), int(ad)))
    return ad_list


def _parse_tuple(ad_str, ad_list):
    if not ad_str:
        copied = copy.copy(ad_list)
        random.shuffle(copied)
        return copied
    isd, ad = ad_str.split(",")
    return [(int(isd), int(ad))]


def main():
    handle_signals()
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--client', help='Client address')
    parser.add_argument('-s', '--server', help='Server address')
    parser.add_argument('-m', '--mininet', action='store_true',
                        help="Running under mininet")
    parser.add_argument('src_ad', nargs='?', help='Src isd,ad')
    parser.add_argument('dst_ad', nargs='?', help='Dst isd,ad')
    args = parser.parse_args()
    init_logging("logs/end2end", console_level=logging.DEBUG)

    if not args.client:
        args.client = "169.254.0.2" if args.mininet else "127.0.0.2"
    if not args.server:
        args.server = "169.254.0.3" if args.mininet else "127.0.0.3"

    ad_list = _load_ad_list()
    # srcs = _parse_tuple(args.src_ad, ad_list)
    # dsts = _parse_tuple(args.dst_ad, ad_list)

    TestSCIONDaemon().test(args.client, args.server, [(1, 17)], [(2, 25)])


if __name__ == "__main__":
    main_wrapper(main)
