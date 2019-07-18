# Copyright 2019 James Brown
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import logging

from base64 import b16encode
from enum import Flag, auto, unique

import requests
from requests.exceptions import ConnectionError

from torpy.utils import to_hex, cached_property, fp_to_str
from torpy.parsers import RouterDescriptorParser


logger = logging.getLogger(__name__)


class Descriptor:
    def __init__(self, onion_key, signing_key, ntor_key):
        self._onion_key = onion_key
        self._signing_key = signing_key
        self._ntor_key = ntor_key

    @property
    def onion_key(self):
        return self._onion_key

    @property
    def signing_key(self):
        return self._signing_key

    @property
    def ntor_key(self):
        return self._ntor_key


class OnionRouter:
    def __init__(self, nickname, ip, dir_port, tor_port, fingerprint, flags, version, consensus=None):
        self._nickname = nickname
        self._ip = ip
        self._dir_port = dir_port
        self._tor_port = tor_port
        self._fingerprint = fingerprint
        self._flags = flags
        self._version = version

        self._consensus = consensus
        # Should be filled later
        self._descriptor = None
        self._service_key = None

    @property
    def nickname(self):
        return self._nickname

    @property
    def ip(self):
        return self._ip

    @property
    def dir_port(self):
        return self._dir_port

    @property
    def tor_port(self):
        return self._tor_port

    @property
    def fingerprint(self):
        return self._fingerprint

    @property
    def flags(self):
        return self._flags

    @property
    def version(self):
        return self._version

    @cached_property
    def descriptor(self):
        logger.debug('Getting descriptor for %s...', self)
        return self._consensus.get_descriptor(self.fingerprint)

    @property
    def service_key(self):
        return self._service_key

    @service_key.setter
    def service_key(self, value):
        self._service_key = value

    @property
    def descriptor_url_prefix(self):
        """
        The URL to the onion router's descriptor (where keys are stored).
        :return: URL
        """
        return 'http://{}:{}/tor/server/fp'.format(self.ip, self.dir_port)

    def descriptor_url(self, fingerprint):
        return '{}/{}'.format(self.descriptor_url_prefix, b16encode(fingerprint).decode())

    def get_descriptor_for(self, fingerprint):
        """
        Get another router descriptor through this one
        :param fingerprint:
        :return: Descriptor object
        """
        logger.debug('Getting descriptor for %s from %s', fp_to_str(fingerprint), self)

        url = self.descriptor_url(fingerprint)
        try:
            response = requests.get(url, timeout=3)
        except (ConnectionError, ) as e:
            logger.debug(e)
            raise Exception("Can't fetch descriptor from %s" % url)

        descriptor_info = RouterDescriptorParser.parse(response.text)
        return Descriptor(**descriptor_info)

    def __str__(self):
        return '{}:{} ({}; {})'.format(self.ip, self.tor_port, self.nickname, self.version)


@unique
class RouterFlags(Flag):
    unknown = 0
    stable = auto()
    fast = auto()
    valid = auto()
    running = auto()
    guard = auto()
    exit = auto()
    hsdir = auto()
    v2dir = auto()

    def all_present(self, flags_list):
        return all(self & flag for flag in flags_list)
