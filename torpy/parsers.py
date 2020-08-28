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

import re
import logging

from torpy.crypto_common import b64decode

logger = logging.getLogger(__name__)


class HSDescriptorParser:
    regex = re.compile(
        """\
introduction-points
-----BEGIN MESSAGE-----
(.+?)
-----END MESSAGE-----""",
        flags=re.DOTALL | re.IGNORECASE,
    )

    @staticmethod
    def parse(data):
        m = __class__.regex.search(data)
        if m:
            return m.group(1)
        else:
            logger.error("Can't parse HSDescriptor: %r", data)
            raise Exception("Can't parse HSDescriptor")


class RouterDescriptorParser:
    regex = re.compile(
        r"""\
onion-key
-----BEGIN RSA PUBLIC KEY-----
(?P<onion_key>.+?)
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
(?P<signing_key>.+?)
-----END RSA PUBLIC KEY-----
.+?
ntor-onion-key (?P<ntor_key>[^\n]+)""",
        flags=re.DOTALL | re.IGNORECASE,
    )

    @staticmethod
    def parse(data):
        m = __class__.regex.search(data)
        if m:
            return {k: b64decode(v) for k, v in m.groupdict().items()}
        else:
            logger.debug("Can't parse router descriptor: %r", data)
            raise Exception("Can't parse router descriptor")


class IntroPointParser:
    regex = re.compile(
        r"""\
introduction-point (?P<introduction_point>[^\n]+)
ip-address (?P<ip_address>[^\n]+)
onion-port (?P<port>[0-9]+)
onion-key
-----BEGIN RSA PUBLIC KEY-----
(?P<onion_key>.+?)
-----END RSA PUBLIC KEY-----
service-key
-----BEGIN RSA PUBLIC KEY-----
(?P<service_key>.+?)
-----END RSA PUBLIC KEY-----""",
        flags=re.DOTALL | re.IGNORECASE,
    )

    @staticmethod
    def _decode(d):
        for k in ('onion_key', 'service_key'):
            d[k] = b64decode(d[k])
        return d

    @staticmethod
    def parse(data):
        res = [__class__._decode(m.groupdict()) for m in __class__.regex.finditer(data)]
        return res
