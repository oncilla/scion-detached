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
# import os
import pstats
import time

import lib.crypto.prp as prp
import lib.privacy.hornet_end_host as hornet

REPEAT_TIMES = 50

# PROFILING_OUTPUT_DIR = "profiling/"
# if not os.path.exists(PROFILING_OUTPUT_DIR):
#     os.makedirs(PROFILING_OUTPUT_DIR)
# output_file = os.path.join(PROFILING_OUTPUT_DIR, "hornet_end_host_profiling")

def print_heading(heading):
    """Print heading"""
    print("#####  " + str(heading) + "  #####\n")
    print(time.strftime('%Y-%m-%d %H:%M:%S') + "\n")


def profile_whole_run():
    """
    Profile the entire protocol run, including the setup and a forward and
    a backward data message.
    """
    print_heading("Profiling entire Hornet protocol")
    profiler = cProfile.Profile()

    profiler.enable()
    for _ in range(REPEAT_TIMES):
        hornet.test()
    profiler.disable()

    profiling_stats = pstats.Stats(profiler)
    profiling_stats.sort_stats('cumulative').print_stats()


def profile_prp():
    """
    Profile a PRP encryption and decryption.
    """
    print_heading("Profiling PRP")
    profiler = cProfile.Profile()

    profiler.enable()
    for _ in range(REPEAT_TIMES):
        prp.test()
    profiler.disable()

    profiling_stats = pstats.Stats(profiler)
    profiling_stats.strip_dirs().sort_stats('cumulative').print_stats()


if __name__ == '__main__':
    profile_whole_run()
    profile_prp()
