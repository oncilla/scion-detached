# Copyright 2014 ETH Zurich

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`sphinx_node` --- Sphinx node
==================================

This module defines the Sphinx node, main processing unit of the Sphinx protocol.

"""

class SphinxNode(object):
    """
    
    """

    def __init__(self, name):
        """
        Create a new SphinxNode
        """
        self._public_key = None
        self._private_key = None
        self.name = name

    def process_packet(self, packet):
        """
        Process a Sphinx packet
        """
        pass