"""
:mod:`profiling` --- Profiling for HORNET
=========================================

Profiling for the HORNET protocol.

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
import cProfile
import os
import pstats
import time

from lib.privacy.common.constants import DEFAULT_MAX_HOPS,\
    DEFAULT_ADDRESS_LENGTH
from curve25519.keys import Private
from lib.privacy.hornet_end_host import HornetSource, HornetDestination
from lib.privacy.hornet_node import HornetNode

REPEAT_TIMES = 20

# PROFILING_OUTPUT_DIR = "profiling/"
# if not os.path.exists(PROFILING_OUTPUT_DIR):
#     os.makedirs(PROFILING_OUTPUT_DIR)
# output_file = os.path.join(PROFILING_OUTPUT_DIR, "hornet_end_host_profiling")

def print_heading(heading, print_time=True):
    """Print heading"""
    print("#####  " + str(heading) + "  #####\n")
    if print_time:
        print(time.strftime('%Y-%m-%d %H:%M:%S') + "\n")


def profile_whole_protocol():
    """
    Profile the entire protocol run, including the setup and a forward and
    a backward data message.
    """
    profiler = cProfile.Profile()

    ######################################################################
    max_hops = DEFAULT_MAX_HOPS
    number_of_intermediate_nodes = 5
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
    ######################################################################

    profiler.enable()
    for _ in range(REPEAT_TIMES):
        # Source creates first setup packet
        source_session_id, source_packet = source.create_new_session_request(
            fwd_path, fwd_pubkeys, bwd_path, bwd_pubkeys,
            session_expiration_time)
        raw_packet = source_packet.pack()

        # Intermediate nodes process first setup packet
        for node in nodes:
            result = node.process_incoming_packet(raw_packet)
            raw_packet = result.packet_to_send.pack()

        # Destination processes first setup packet and creates the second
        result = destination.process_incoming_packet(raw_packet)
        raw_packet = result.packet_to_send.pack()

        # Intermediate nodes process second setup packet
        for node in reversed(nodes):
            result = node.process_incoming_packet(raw_packet)
            raw_packet = result.packet_to_send.pack()

        # Source processes second setup packet and creates the third (data)
        result = source.process_incoming_packet(raw_packet)
        raw_packet = result.packet_to_send.pack()

        # Intermediate nodes process data packet
        for node in nodes:
            result = node.process_incoming_packet(raw_packet)
            raw_packet = result.packet_to_send.pack()

        # Destination processes third setup packet (data) and stores session
        result = destination.process_incoming_packet(raw_packet)
    profiler.disable()

    profiling_stats = pstats.Stats(profiler)
    print_heading("Profiling Hornet setup")
    profiling_stats.sort_stats('cumulative').print_stats(25)

    profiler = cProfile.Profile()

    # Source packet
    raw_packet = source_packet.pack()

    profiler.enable()
    for _ in range(REPEAT_TIMES):
        # First node processes first setup packet
        nodes[0].process_incoming_packet(raw_packet).packet_to_send.pack()
    profiler.disable()

    profiling_stats = pstats.Stats(profiler)
    print_heading("Profiling Node setup packet processing")
    profiling_stats.sort_stats('cumulative').print_stats(25)

    profiler = cProfile.Profile()

    profiler.enable()
    for _ in range(REPEAT_TIMES):
        data = b'1'*10

        # Source creates data packet
        data_packet = source.construct_data_packet(source_session_id, data)
        raw_packet = data_packet.pack()

        # Intermediate nodes process data packet
        for node in nodes:
            result = node.process_incoming_packet(raw_packet)
            raw_packet = result.packet_to_send.pack()

        # Destination processes data packet and obtains data
        destination.process_incoming_packet(raw_packet)
    profiler.disable()

    profiling_stats = pstats.Stats(profiler)
    print_heading("Profiling Hornet data transmission")
    profiling_stats.sort_stats('cumulative').print_stats(25)

    profiler = cProfile.Profile()

    # Source creates data packet
    raw_packet = data_packet.pack()

    profiler.enable()
    for _ in range(100):
        # First node processes data packet
        nodes[0].process_incoming_packet(raw_packet).packet_to_send.pack()
    profiler.disable()

    profiling_stats = pstats.Stats(profiler)
    print_heading("Profiling node data packet processing")
    profiling_stats.sort_stats('cumulative').print_stats(30)


if __name__ == '__main__':
    profile_whole_protocol()
