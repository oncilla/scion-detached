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
import os
import pickle
import statistics
import time
import timeit
from lib.privacy.common.constants import DEFAULT_MAX_HOPS,\
    DEFAULT_ADDRESS_LENGTH
from test.privacy.profiling import print_heading
import datetime
from math import sqrt
import itertools

EXPERIMENT_OUTPUT_DIR = "results"

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


def get_unique_filename(base_path, extension='', timestamp=None):
    """
    Returns a filename based on base_path by appending a timestamp, checking
    if it exists, and in case adding a sequence number to the end.
    """
    assert isinstance(base_path, str)
    assert isinstance(extension, str)
    if timestamp is None:
        timestr = time.strftime("%Y%m%d-%H%M%S")
    else:
        timestr = timestamp.strftime("%Y%m%d-%H%M%S")
    if not os.path.exists(base_path + '_' + timestr + extension):
        return base_path + '_' + timestr + extension
    counter = 1
    while True:
        path = base_path + '_' + timestr + '_' + str(counter) + extension
        if not os.path.exists(path):
            return path
        counter += 1


class ExperimentData(object):
    """
    Data of an experiment (object to be serialized with JSON)
    """

    def __init__(self, experiment_type, experiment_start, experiment_end,
                 replications, sample_size, repetitions_per_sample,
                 number_of_hops, max_hops, replicates):
        assert replications > 0
        assert sample_size > 1
        assert len(replicates) == replications
        for replicate in replicates:
            assert len(replicate) == sample_size
        self.experiment_type = experiment_type
        self.experiment_start = experiment_start
        self.experiment_end = experiment_end
        self.replications = replications
        self.sample_size = sample_size
        # Number of consecutive repetitions of the code within one sample
        self.repetitions_per_sample = repetitions_per_sample
        self.number_of_hops = number_of_hops
        self.max_hops = max_hops
        self.replicates = replicates

    def store(self, base_filename="experiment_data"):
        """
        Store the data of the experiment.
        """
        if not os.path.exists(EXPERIMENT_OUTPUT_DIR):
            os.makedirs(EXPERIMENT_OUTPUT_DIR)
        base_path = os.path.join(EXPERIMENT_OUTPUT_DIR, base_filename)
        output_path = get_unique_filename(base_path, extension=".pickle",
                                          timestamp=self.experiment_start)
        with open(output_path, 'wb') as file:
            pickle.dump(self, file)
        return output_path

    @staticmethod
    def retrieve_experiment_data(experiment_path):
        """
        Retrieves the data of an experiment stored at experiment_path with
        :func:`store_experiment_data`.
        """
        with open(experiment_path, 'rb') as file:
            loaded_obj = pickle.load(file)
        if isinstance(loaded_obj, ExperimentData):
            return loaded_obj
        else:
            raise TypeError("The data loaded from the pickle file is not "
                            "an instance of ExperimentData")

    def print_aggregated_data(self):
        """
        Prints the aggregated data from the experiment
        """
        means = [statistics.mean(r) for r in self.replicates]
        variances = [statistics.variance(r) for r in self.replicates]
        best_times = [min(r) for r in self.replicates]
        mean = statistics.mean(means)
        stdev = sqrt(statistics.mean(variances))
        best_time = min(best_times)

        print_heading(self.experiment_type, print_time=False)
        print("Hops (Max): {}({})"
              .format(self.number_of_hops, self.max_hops))
        print()
        print("Replications: " + str(self.replications))
        print("Sample size:  " + str(self.sample_size))
        print("Repetitions per sample: " + str(self.repetitions_per_sample))
        print()
        print("Experiment started at:    " +
              str(self.experiment_start.isoformat()))
        print("Experiment completed at:  " +
              str(self.experiment_end.isoformat()))
        print()
        print("Estimated mean:  " + str(mean))
        print("Best time (min): " + str(best_time))
        print("Estimated stdev: " + str(stdev))
        print()


def time_setup(replications=5, sample_size=1000, number_of_hops=5,
               max_hops=DEFAULT_MAX_HOPS):
    """
    Measure the time required for a Hornet setup
    """
    assert replications > 0
    assert sample_size > 1
    repetitions_per_sample = 1
    timer = timeit.Timer(HORNET_SETUP_PHASE_STMT,
                         setup=get_init_stmt(number_of_hops, max_hops))
    # Warm up
    _ = timer.timeit(number=500)

    # Actual experiment
    replicates = []
    experiment_start = datetime.datetime.now()
    for _ in range(replications):
        samples = timer.repeat(repeat=sample_size,
                               number=repetitions_per_sample)
        replicates.append(samples)
    experiment_end = datetime.datetime.now()

    data = ExperimentData("Setup timing", experiment_start,
                          experiment_end, replications, sample_size,
                          repetitions_per_sample,
                          number_of_hops, max_hops, replicates)
    data.store(base_filename="setup_timing")
    data.print_aggregated_data()


def time_data(number_of_packets, replications=5, sample_size=1000,
              number_of_hops=5, max_hops=DEFAULT_MAX_HOPS):
    """
    Measure the time required for the transmission of number_of_packets
    data packets.
    """
    assert replications > 0
    assert sample_size > 1
    setup_stmt = (get_init_stmt(number_of_hops, max_hops) +
                  HORNET_SETUP_PHASE_STMT)
    timer = timeit.Timer(HORNET_TRANSMIT_DATA_STMT,
                         setup=setup_stmt)
    # Warm up
    _ = timer.timeit(number=500)

    # Actual experiment
    replicates = []
    experiment_start = datetime.datetime.now()
    for _ in range(replications):
        samples = timer.repeat(repeat=sample_size, number=number_of_packets)
        replicates.append(samples)
    experiment_end = datetime.datetime.now()

    experiment_name = ("Data transmission timing, {} packets"
                       .format(number_of_packets))
    data = ExperimentData(experiment_name,
                          experiment_start, experiment_end,
                          replications, sample_size,
                          number_of_packets,
                          number_of_hops, max_hops, replicates)
    data.store(base_filename="data_timing_{}_pkts".format(number_of_packets))
    data.print_aggregated_data()

if __name__ == '__main__':
    all_hops=[3, 4, 5, 6]
    all_max_hops=[7, 10]
    for number_of_hops, max_hops in itertools.product(all_hops, all_max_hops):
        time_setup(replications=4, sample_size=100,
                   number_of_hops=number_of_hops, max_hops=max_hops)
        time_data(1, replications=4, sample_size=100,
                   number_of_hops=number_of_hops, max_hops=max_hops)
    # Retrieve data from file
#     ExperimentData.retrieve_experiment_data(
#         "results/setup_timing_20150325-123539.pickle").print_aggregated_data()

