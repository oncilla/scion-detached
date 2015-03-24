"""
:mod:`timing` --- Timing measurements for HORNET
================================================

Timing measurements for the HORNET protocol.

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
import statistics
import timeit
from lib.privacy.common.constants import DEFAULT_MAX_HOPS,\
    DEFAULT_ADDRESS_LENGTH
from lib.privacy.hornet_packet import DATA_PAYLOAD_LENGTH
from test.privacy.profiling import print_heading

_INIT_STMT = """
from lib.privacy.common.constants import DEFAULT_MAX_HOPS
from curve25519.keys import Private
from lib.privacy.hornet_end_host import HornetSource, HornetDestination
from lib.privacy.hornet_node import HornetNode
import os
import time

DEFAULT_ADDRESS_LENGTH={2}

number_of_hops={0}
max_hops={1}

number_of_intermediate_nodes = number_of_hops - 1

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
"""

HORNET_SETUP_PHASE_STMT = """
# Source creates first setup packet
source_session_id, packet = source.create_new_session_request(
    fwd_path, fwd_pubkeys, bwd_path, bwd_pubkeys, session_expiration_time)
raw_packet = packet.pack()

# Intermediate nodes process first setup packet
for i, node in enumerate(nodes):
    result = node.process_incoming_packet(raw_packet)
    raw_packet = result.packet_to_send.pack()

# Destination processes first setup packet and creates second setup packet
result = destination.process_incoming_packet(raw_packet)
raw_packet = result.packet_to_send.pack()

# Intermediate nodes process second setup packet
for i, node in enumerate(reversed(nodes)):
    result = node.process_incoming_packet(raw_packet)
    raw_packet = result.packet_to_send.pack()

# Source processes second setup packet and creates third setup packet (data)
result = source.process_incoming_packet(raw_packet)
raw_packet = result.packet_to_send.pack()

# Intermediate nodes process data packet
for i, node in enumerate(nodes):
    result = node.process_incoming_packet(raw_packet)
    raw_packet = result.packet_to_send.pack()

# Destination processes third setup packet (data) and stores session
result = destination.process_incoming_packet(raw_packet)
dest_session_id = result.session_id
"""

HORNET_TRANSMIT_DATA_STMT = """
data = b'1'*10

# Source creates data packet
data_packet = source.construct_data_packet(source_session_id, data)
raw_packet = data_packet.pack()

# Intermediate nodes process data packet
for i, node in enumerate(nodes):
    result = node.process_incoming_packet(raw_packet)
    raw_packet = result.packet_to_send.pack()

# Destination processes data packet and obtains data
destination.process_incoming_packet(raw_packet)
"""

def get_init_stmt(number_of_hops=5, max_hops=DEFAULT_MAX_HOPS):
    """
    Returns the setup statement formatted correctly (inserting the parameters)
    """
    assert number_of_hops <= max_hops
    return _INIT_STMT.format(number_of_hops, max_hops, DEFAULT_ADDRESS_LENGTH)


def time_setup(replications=5, sample_size=1000, number_of_hops=5,
               max_hops=DEFAULT_MAX_HOPS):
    """
    Measure the time required for a Hornet setup
    """
    timer = timeit.Timer(HORNET_SETUP_PHASE_STMT,
                         setup=get_init_stmt(number_of_hops, max_hops))
    # Warm up
    _ = timer.timeit(number=500)

    # Actual experiment
    replicates = []
    for _ in range(replications):
        samples = timer.repeat(repeat=sample_size, number=1)
        replicates.append(samples)
    #TODO:Daniele: store experiments
    means = [statistics.mean(r) for r in replicates]
    stdevs = [statistics.stdev(r) for r in replicates]
    print_heading("Setup")
    print("Estimated mean: " + str(statistics.mean(means)))
    print("Estimated stdev: " + str(statistics.mean(stdevs)))


def time_data(number_of_packets, replications=5, sample_size=1000,
              number_of_hops=5, max_hops=DEFAULT_MAX_HOPS):
    """
    Measure the time required for the transmission of number_of_packets
    data packets.
    """
    setup_stmt = (get_init_stmt(number_of_hops, max_hops) +
                  HORNET_SETUP_PHASE_STMT)
    timer = timeit.Timer(HORNET_TRANSMIT_DATA_STMT,
                         setup=setup_stmt)
    # Warm up
    _ = timer.timeit(number=500)

    # Actual experiment
    replicates = []
    for _ in range(replications):
        samples = timer.repeat(repeat=sample_size, number=number_of_packets)
        replicates.append(samples)
    #TODO:Daniele: store experiments
    means = [statistics.mean(r) for r in replicates]
    stdevs = [statistics.stdev(r) for r in replicates]
    print_heading("Data transmission")
    print("Estimated mean: " + str(statistics.mean(means)))
    print("Estimated stdev: " + str(statistics.mean(stdevs)))

if __name__ == '__main__':
    time_setup(replications=5, sample_size=100)
    bytes_to_transmit = 1000000 # 1MB
    packets_to_transmit = bytes_to_transmit // (DATA_PAYLOAD_LENGTH-1)
    time_data(packets_to_transmit, replications=3, sample_size=5)

