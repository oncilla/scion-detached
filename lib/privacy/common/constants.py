"""
:mod:`constants` --- Constants of the privacy package
=====================================================

This module defines the constants for the privacy package.

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

# Default maximum number of hops on a path, including the destination
DEFAULT_MAX_HOPS = 8
DEFAULT_ADDRESS_LENGTH = 16 # Default size of a node's address/name in bytes
# Default size of a group element (for Diffie-Hellman) in bytes
GROUP_ELEM_LENGTH = 32
MAC_SIZE = 8 # Size of a Message Authentication Code in bytes
LOCALHOST_ADDRESS = b"0" * DEFAULT_ADDRESS_LENGTH

