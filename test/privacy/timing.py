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

DEFAULT_REPLICATIONS = 4
DEFAULT_SAMPLE_SIZE = 100
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

SOURCE_NEW_SESSION = """
_, packet = source.create_new_session_request(fwd_path, fwd_pubkeys, bwd_path,
                                              bwd_pubkeys,
                                              session_expiration_time)
raw_packet = packet.pack()
"""

NODE_PROCESS_PACKET_STMT = """
nodes[0].process_incoming_packet(raw_packet).packet_to_send.pack()
"""

INIT_FOR_DEST_SETUP = """
# Source creates first setup packet
source_session_id, packet = source.create_new_session_request(
    fwd_path, fwd_pubkeys, bwd_path, bwd_pubkeys, session_expiration_time)
raw_packet = packet.pack()

# Intermediate nodes process first setup packet
for i, node in enumerate(nodes):
    result = node.process_incoming_packet(raw_packet)
    raw_packet = result.packet_to_send.pack()
"""

DEST_SETUP = """
# Destination processes first setup packet and creates second setup packet
result = destination.process_incoming_packet(raw_packet)
raw_packet = result.packet_to_send.pack()
"""

INIT_FOR_SOURCE_2 = """
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
"""

SOURCE_2 = """
# Source processes second setup packet and creates third setup packet (data)
result = source.process_incoming_packet(raw_packet)
raw_packet = result.packet_to_send.pack()
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

SOURCE_SEND_PACKET = """
data = b'1'*10

raw_packet = source.construct_data_packet(source_session_id, data).pack()
"""

INIT_FOR_DEST_DATA = """
data = b'1'*10

# Source creates data packet
data_packet = source.construct_data_packet(source_session_id, data)
raw_packet = data_packet.pack()

# Intermediate nodes process data packet
for i, node in enumerate(nodes):
    result = node.process_incoming_packet(raw_packet)
    raw_packet = result.packet_to_send.pack()
"""

DEST_DATA = """
# Destination processes data packet and obtains data
destination.process_incoming_packet(raw_packet)
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
        print("Estimated mean:  {:.6f}".format(mean))
        print("Best time (min): {:.6f}".format(best_time))
        print("Estimated stdev: {:.6f}".format(stdev))
        print()

    def print_compact(self):
        """
        Prints the aggregated data of the experiment in one line
        """
        means = [statistics.mean(r) for r in self.replicates]
        variances = [statistics.variance(r) for r in self.replicates]
        best_times = [min(r) for r in self.replicates]
        mean = statistics.mean(means)
        stdev = sqrt(statistics.mean(variances))
        best_time = min(best_times)

        print("{}\t{}({}):\t{:.6f}\t{:.6f}\t{:.6f}"
              .format(self.experiment_type, self.number_of_hops,
                      self.max_hops, mean, best_time, stdev))


def time_statement(experiment_type, base_filename, stmt="pass",
                   init_stmt="pass", replications=DEFAULT_REPLICATIONS,
                   sample_size=DEFAULT_SAMPLE_SIZE, repetitions_per_sample = 1,
                   number_of_hops=5, max_hops=DEFAULT_MAX_HOPS):
    """
    Measure the time required to execute statement stmt, store the result in a
    :class:`ExperimentData` instance and return the path of the stored data.
    """
    assert replications > 0
    assert sample_size > 1
    timer = timeit.Timer(stmt, setup=init_stmt)
    # Warm up
    _ = timer.repeat(repeat=10, number=1)

    # Actual experiment
    replicates = []
    experiment_start = datetime.datetime.now()
    for _ in range(replications):
        samples = timer.repeat(repeat=sample_size,
                               number=repetitions_per_sample)
        replicates.append(samples)
    experiment_end = datetime.datetime.now()

    data = ExperimentData(experiment_type, experiment_start,
                          experiment_end, replications, sample_size,
                          repetitions_per_sample,
                          number_of_hops, max_hops, replicates)
    output_path = data.store(base_filename=base_filename)
    data.print_aggregated_data()
    return output_path


def time_setup(replications=DEFAULT_REPLICATIONS,
               sample_size=DEFAULT_SAMPLE_SIZE, number_of_hops=5,
               max_hops=DEFAULT_MAX_HOPS):
    """
    Measure the time required for a Hornet setup
    """
    output_path = time_statement("Complete setup", 'setup',
                                 HORNET_SETUP_PHASE_STMT,
                                 get_init_stmt(number_of_hops, max_hops),
                                 replications, sample_size, 1, number_of_hops,
                                 max_hops)
    return output_path


def time_source_new_session(replications=DEFAULT_REPLICATIONS,
                            sample_size=DEFAULT_SAMPLE_SIZE, number_of_hops=5,
                            max_hops=DEFAULT_MAX_HOPS):
    """
    Measure the time required for a source to create a session request
    (first setup packet)
    """
    output_path = time_statement("Source sess req", 'source_sess_req',
                                 SOURCE_NEW_SESSION,
                                 get_init_stmt(number_of_hops, max_hops),
                                 replications, sample_size, 1, number_of_hops,
                                 max_hops)
    return output_path


def time_node_setup_packet(replications=DEFAULT_REPLICATIONS,
                           sample_size=DEFAULT_SAMPLE_SIZE, number_of_hops=5,
                           max_hops=DEFAULT_MAX_HOPS):
    """
    Measure the time required for a node to process a setup packet
    """
    output_path = time_statement("Node stp proc", 'node_setup',
                                 NODE_PROCESS_PACKET_STMT,
                                 get_init_stmt(number_of_hops, max_hops)
                                 + SOURCE_NEW_SESSION,
                                 replications, sample_size, 1, number_of_hops,
                                 max_hops)
    return output_path


def time_dest_setup_packet(replications=DEFAULT_REPLICATIONS,
                           sample_size=DEFAULT_SAMPLE_SIZE, number_of_hops=5,
                           max_hops=DEFAULT_MAX_HOPS):
    """
    Measure the time required the destination to process the first setup packet
    and create the second.
    """
    output_path = time_statement("Dest stp proc", 'dest_setup',
                                 DEST_SETUP,
                                 get_init_stmt(number_of_hops, max_hops)
                                 + INIT_FOR_DEST_SETUP,
                                 replications, sample_size, 1, number_of_hops,
                                 max_hops)
    return output_path


def time_source_setup_packet(replications=DEFAULT_REPLICATIONS,
                             sample_size=DEFAULT_SAMPLE_SIZE, number_of_hops=5,
                             max_hops=DEFAULT_MAX_HOPS):
    """
    Measure the time required by the source to process the second setup packet.
    """
    output_path = time_statement("Source stp proc", 'source_setup',
                                 SOURCE_2,
                                 get_init_stmt(number_of_hops, max_hops)
                                 + INIT_FOR_SOURCE_2,
                                 replications, sample_size, 1, number_of_hops,
                                 max_hops)
    return output_path


################ DATA #################


def time_source_data_packet(replications=DEFAULT_REPLICATIONS,
                            sample_size=DEFAULT_SAMPLE_SIZE, number_of_hops=5,
                            max_hops=DEFAULT_MAX_HOPS):
    """
    Measure the time required for a source to create a data packet.
    """
    setup_stmt = (get_init_stmt(number_of_hops, max_hops) +
                  HORNET_SETUP_PHASE_STMT)
    output_path = time_statement("Source data pkt", 'source_data',
                                 SOURCE_SEND_PACKET, setup_stmt,
                                 replications, sample_size, 1, number_of_hops,
                                 max_hops)
    return output_path


def time_node_data_packet(replications=DEFAULT_REPLICATIONS,
                          sample_size=DEFAULT_SAMPLE_SIZE, number_of_hops=5,
                          max_hops=DEFAULT_MAX_HOPS):
    """
    Measure the time required for a source to create a data packet.
    """
    setup_stmt = (get_init_stmt(number_of_hops, max_hops) +
                  HORNET_SETUP_PHASE_STMT + SOURCE_SEND_PACKET)
    output_path = time_statement("Node data pkt", 'node_data',
                                 NODE_PROCESS_PACKET_STMT, setup_stmt,
                                 replications, sample_size, 1, number_of_hops,
                                 max_hops)
    return output_path


def time_dest_data_packet(replications=DEFAULT_REPLICATIONS,
                          sample_size=DEFAULT_SAMPLE_SIZE, number_of_hops=5,
                          max_hops=DEFAULT_MAX_HOPS):
    """
    Measure the time required by the destination to process an incoming data
    packet.
    """
    setup_stmt = (get_init_stmt(number_of_hops, max_hops) +
                  HORNET_SETUP_PHASE_STMT + INIT_FOR_DEST_DATA)
    output_path = time_statement("Dest data pkt", 'dest_data',
                                 DEST_DATA, setup_stmt,
                                 replications, sample_size, 1, number_of_hops,
                                 max_hops)
    return output_path


def time_data(number_of_packets, replications=DEFAULT_REPLICATIONS,
              sample_size=DEFAULT_SAMPLE_SIZE, number_of_hops=5,
              max_hops=DEFAULT_MAX_HOPS):
    """
    Measure the time required for the transmission of number_of_packets
    data packets.
    """
    setup_stmt = (get_init_stmt(number_of_hops, max_hops) +
                  HORNET_SETUP_PHASE_STMT)
    output_path = time_statement("Complete data", 'data',
                                 HORNET_TRANSMIT_DATA_STMT,
                                 setup_stmt, replications, sample_size,
                                 number_of_packets, number_of_hops, max_hops)
    return output_path


def print_all_experiments(path_list):
    """
    Print all the experiments whose paths were passed as input list
    """
    for path in path_list:
        data = ExperimentData.retrieve_experiment_data(path)
        data.print_compact()


def run_all_experiments():
    """
    Run all the experiments
    """
    all_hops = [2, 3, 4, 5, 6, 7]
    all_max_hops = [8]
    experiments_paths = []

    for number_of_hops, max_hops in itertools.product(all_hops, all_max_hops):
        # Setup
        experiments_paths.append(time_setup(number_of_hops=number_of_hops,
                                            max_hops=max_hops))
        experiments_paths.append(time_source_new_session(
            number_of_hops=number_of_hops, max_hops=max_hops))
        experiments_paths.append(time_node_setup_packet(
            number_of_hops=number_of_hops, max_hops=max_hops))
        experiments_paths.append(time_dest_setup_packet(
            number_of_hops=number_of_hops, max_hops=max_hops))
        experiments_paths.append(time_source_setup_packet(
            number_of_hops=number_of_hops, max_hops=max_hops))
        # Data
        experiments_paths.append(time_source_data_packet(
            number_of_hops=number_of_hops, max_hops=max_hops))
        experiments_paths.append(time_node_data_packet(
            number_of_hops=number_of_hops, max_hops=max_hops))
        experiments_paths.append(time_dest_data_packet(
            number_of_hops=number_of_hops, max_hops=max_hops))
        experiments_paths.append(time_data(1, number_of_hops=number_of_hops,
                                           max_hops=max_hops))
    print_all_experiments(experiments_paths)


if __name__ == '__main__':
    run_all_experiments()
    # Retrieve data from file
#     ExperimentData.retrieve_experiment_data(
#         "results/setup_20150325-123539.pickle").print_aggregated_data()

