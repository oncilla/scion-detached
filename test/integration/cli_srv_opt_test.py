#!/usr/bin/python3
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
:mod:`cli_srv_ext_test` --- SCION client-server test with an extension
======================================================================
"""
# Stdlib
import argparse
import logging
import sys
import threading
import time

from nacl.utils import random as rand_bytes
# SCION
from lib.opt.util import OPTStore, OPTCreatePacketParams, create_scion_udp_packet, is_hash_valid, get_opt_ext_hdr, \
    set_answer_packet
from endhost.sciond import SCIONDaemon
from lib.defines import GEN_PATH, SCION_UDP_EH_DATA_PORT
from lib.log import init_logging
from lib.main import main_wrapper
from lib.packet.host_addr import haddr_parse_interface
from lib.packet.packet_base import PayloadRaw
from lib.packet.scion import SCIONL4Packet
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.socket import UDPSocket
from lib.thread import thread_safety_net
from lib.util import handle_signals

TOUT = 10  # How long wait for response.


def client(c_addr, s_addr):
    """
    Simple client
    """
    conf_dir = "%s/ISD%d/AS%d/endhost" % (
        GEN_PATH, c_addr.isd_as[0], c_addr.isd_as[1])
    # Start SCIONDaemon
    sd = SCIONDaemon.start(conf_dir, c_addr.host)
    opt = OPTStore()
    logging.info("CLI: Sending PATH request for %s", s_addr.isd_as)
    # Open a socket for incomming DATA traffic
    sock = UDPSocket(bind=(str(c_addr.host), 0, "Client"),
                     addr_type=c_addr.host.TYPE)
    # Get paths to server through function call
    paths = sd.get_paths(s_addr.isd_as)
    assert paths
    # Get a first path
    path = paths[0]

    session_id = rand_bytes(16)
    # start DRKey exchange
    sd.init_drkeys(s_addr, path, session_id, non_blocking=True)

    params = OPTCreatePacketParams()
    params.session_id = session_id
    params.dst = s_addr
    params.port_dst = SCION_UDP_EH_DATA_PORT
    params.src = c_addr
    params.port_src = sock.port
    params.path = path
    params.session_key_dst = sd.get_drkeys(session_id).dst_key

    for i in range(10):
        params.payload = PayloadRaw(("request %d to server" % i).encode("utf-8"))

        spkt = create_scion_udp_packet(params)
        next_hop, port = sd.get_first_hop(spkt)
        assert next_hop is not None
        logging.info("CLI: Sending packet:\n%d\nFirst hop: %s:%s",
                     i, next_hop, port)
        sd.send(spkt, next_hop, port)

        raw, _ = sock.recv()
        logging.info('CLI: Received response:\n%s', SCIONL4Packet(raw))
        spkt = SCIONL4Packet(raw)
        opt.insert_packet(spkt)

    sd.send_drkeys(s_addr, path, session_id)
    logging.debug("DRKeys sent")

    assert sd.get_drkeys(session_id).src_key is not None
    assert opt.validate_session(session_id, sd.get_drkeys(session_id))

    logging.debug("OPT Session size: %d", opt.number_of_packets(session_id))

    logging.info("CLI: leaving. (Successful)")
    sock.close()


def server(addr):
    """
    Simple server.
    """
    conf_dir = "%s/ISD%d/AS%d/endhost" % (
        GEN_PATH, addr.isd_as[0], addr.isd_as[1])
    sd = SCIONDaemon.start(conf_dir, addr.host)
    opt = OPTStore()
    sock = UDPSocket(
        bind=(str(addr.host), SCION_UDP_EH_DATA_PORT, "Server"),
        addr_type=addr.host.TYPE
    )

    for i in range(10):
        logging.debug("SRV: waiting for packet %d", i)
        raw, _ = sock.recv()
        # Request received, instantiating SCION packet
        spkt = SCIONL4Packet(raw)
        logging.info('SRV: received: %s', spkt.get_payload()._raw)

        if not is_hash_valid(spkt):
            logging.error("#########################################SRV: data hash is not valid")
            sys.exit(1)
        opt.insert_packet(spkt)

        session_id = get_opt_ext_hdr(spkt).session_id
        set_answer_packet(spkt, PayloadRaw(b"response"), sd.get_drkeys(session_id))
        (next_hop, port) = sd.get_first_hop(spkt)
        assert next_hop is not None
        sd.send(spkt, next_hop, port)

    session_ids = opt.get_sessions()
    for session_id in session_ids:
        drkeys = sd.get_drkeys(session_id)
        while not drkeys.intermediate_keys:
            drkeys = sd.get_drkeys(session_id)
            logging.debug("Waiting for drkeys: %s", session_id)
            time.sleep(0.001)

        logging.critical("DRKeys: %s", drkeys)

        if not opt.validate_session(session_id, drkeys):
            logging.error("Invalid pvfs")
            sock.close()
            sys.exit(1)

    logging.info("SRV: Leaving server. (Successful)")


def main():
    handle_signals()
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--client', help='Client address')
    parser.add_argument('-s', '--server', help='Server address')
    parser.add_argument('-m', '--mininet', action='store_true',
                        help="Running under mininet")
    parser.add_argument('cli_ia', nargs='?', help='Client isd-as',
                        default="1-19")
    parser.add_argument('srv_ia', nargs='?', help='Server isd-as',
                        default="1-13")
    args = parser.parse_args()
    init_logging("logs/c2s_extn", console_level=logging.DEBUG)

    if not args.client:
        args.client = "169.254.0.2" if args.mininet else "127.0.0.2"
    if not args.server:
        args.server = "169.254.0.3" if args.mininet else "127.0.0.3"

    srv_ia = ISD_AS(args.srv_ia)
    srv_addr = SCIONAddr.from_values(srv_ia, haddr_parse_interface(args.server))
    threading.Thread(
        target=thread_safety_net, args=(server, srv_addr),
        name="C2S_extn.server", daemon=True).start()
    time.sleep(1)

    cli_ia = ISD_AS(args.cli_ia)
    cli_addr = SCIONAddr.from_values(cli_ia, haddr_parse_interface(args.client))
    t_client = threading.Thread(
        target=thread_safety_net, args=(
            client, cli_addr, srv_addr,
        ), name="C2S_extn.client", daemon=True)
    t_client.start()
    t_client.join()

if __name__ == "__main__":
    main_wrapper(main)
