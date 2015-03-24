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
import timeit
from lib.privacy.common.constants import DEFAULT_MAX_HOPS

setup_statement = """
from lib.privacy.common.constants import DEFAULT_MAX_HOPS
from curve25519.keys import Private
from lib.privacy.hornet_end_host import HornetSource, HornetDestination
from lib.privacy.hornet_node import HornetNode
import time

max_hops=DEFAULT_MAX_HOPS

# Source
source_private = Private(secret=b'S'*32)
source_secret_key = b's'*32
source = HornetSource(source_secret_key, source_private, max_hops=max_hops)

# Nodes
node_1_private = Private(secret=b'A'*32)
node_2_private = Private(secret=b'B'*32)
node_1_secret_key = b'1'*32
node_2_secret_key = b'2'*32
node_1 = HornetNode(node_1_secret_key, node_1_private, max_hops=max_hops)
node_2 = HornetNode(node_2_secret_key, node_2_private, max_hops=max_hops)

# Destination
dest_private = Private(secret=b'D'*32)
dest_secret_key = b'd'*32
destination = HornetDestination(dest_secret_key, dest_private,
                                max_hops=max_hops)

# Source session request
fwd_path = [b'1'*16, b'2'*16, b'dest_address0000']
bwd_path = [b'2'*16, b'1'*16, b'source_address00']
fwd_pubkeys = [node_1_private.get_public(), node_2_private.get_public(),
                destination.public]
bwd_pubkeys = [fwd_pubkeys[1], fwd_pubkeys[0], source.public]
session_expiration_time = int(time.time()) + 600
"""

create_session_statement = """
_, packet = source.create_new_session_request(fwd_path, fwd_pubkeys,
                                              bwd_path, bwd_pubkeys,
                                              session_expiration_time)
packet.pack()
"""


def time_setup(repeat=1000):
    """
    Measure the time required for a Hornet setup
    """
    timer = timeit.Timer(create_session_statement, setup=setup_statement)
    measured_time = timer.timeit(repeat)/1000
    print(str(measured_time))

if __name__ == '__main__':
    time_setup()

