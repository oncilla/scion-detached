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

SETUP_STMT = """
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

CREATE_SESSION_STMT = """
_, packet = source.create_new_session_request(fwd_path, fwd_pubkeys,
                                              bwd_path, bwd_pubkeys,
                                              session_expiration_time)
packet.pack()
"""


def get_setup_stmt(number_of_hops=5, max_hops=DEFAULT_MAX_HOPS):
    assert number_of_hops <= max_hops
    return SETUP_STMT.format(number_of_hops, max_hops, DEFAULT_ADDRESS_LENGTH)


def time_setup(repetitions=3, samples_per_repetition=1000, number_of_hops=5,
               max_hops=DEFAULT_MAX_HOPS):
    """
    Measure the time required for a Hornet setup
    """
    timer = timeit.Timer(CREATE_SESSION_STMT,
                         setup=get_setup_stmt(number_of_hops, max_hops))
    experiments = []
    for _ in range(repetitions):
        samples = timer.repeat(repeat=samples_per_repetition, number=1)
        experiments.append(samples)
    #TODO:Daniele: store experiments
    means = list(map(statistics.mean, experiments))
    stdevs = list(map(statistics.stdev, experiments))
    print("Mean: {}\tStandard Dev.: {}".format(means, stdevs))

if __name__ == '__main__':
    time_setup(repetitions=3, samples_per_repetition=100)

