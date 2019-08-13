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

import random
import logging
import functools
from base64 import b32decode
from threading import Lock

from torpy.utils import retry, log_retry, http_get
from torpy.documents import TorDocumentsFactory
from torpy.documents.network_status import NetworkStatusDocument, RouterFlags
from torpy.documents.network_status_diff import NetworkStatusDiffDocument
from torpy.cache_storage import TorCacheDirStorage

logger = logging.getLogger(__name__)


class DirectoryAuthority:
    """This class represents a directory authority."""

    def __init__(self, name, address, or_port, v3ident, fingerprint, ipv6=None, bridge=False):
        self._name = name
        self._address = address
        self._or_port = or_port
        self._v3ident = v3ident
        self._fingerprint = fingerprint
        self._ipv6 = ipv6
        self._bridge = bridge

    @property
    def name(self):
        """Nickname of this authority."""
        return self._name

    @property
    def status_url(self):
        """Status url of this authority."""
        return 'http://{}/tor/status-vote/current'.format(self._address)

    def download(self, doc_type, prev_hash=None):
        """
        Download <doc_type> from this authority.

        Can raise exceptions if authority not available.
        :return: Consensus text
        """
        # doc_type: consensus, consensus-microdesc, authority?
        add_headers = {'X-Or-Diff-From-Consensus': prev_hash} if prev_hash else None
        return http_get('{}/{}'.format(self.status_url, doc_type), add_headers=add_headers)


class DirectoryAuthoritiesList:
    """Hardcoded into each Tor client is the information about 10 beefy Tor nodes run by trusted volunteers."""

    def __init__(self):
        # tor ref src\app\config\auth_dirs.inc
        self._directory_authorities = [
            DirectoryAuthority('moria1', '128.31.0.34:9131', 9101, 'D586D18309DED4CD6D57C18FDB97EFA96D330566',
                               '9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31'),
            DirectoryAuthority('tor26', '86.59.21.38:80', 443, '14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4',
                               '847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D',
                               ipv6='[2001:858:2:2:aabb:0:563b:1526]:443'),
            DirectoryAuthority('dizum', '194.109.206.212:80', 443, 'E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58',
                               '7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755'),
            DirectoryAuthority('Serge', '66.111.2.131:9030', 9001, None,
                               'BA44 A889 E64B 93FA A2B1 14E0 2C2A 279A 8555 C533',
                               bridge=True),
            DirectoryAuthority('gabelmoo', '131.188.40.189:80', 443, 'ED03BB616EB2F60BEC80151114BB25CEF515B226',
                               'F204 4413 DAC2 E02E 3D6B CF47 35A1 9BCA 1DE9 7281',
                               ipv6='[2001:638:a000:4140::ffff:189]:443'),
            DirectoryAuthority('dannenberg', '193.23.244.244:80', 443, '585769C78764D58426B8B52B6651A5A71137189A',
                               '7BE6 83E6 5D48 1413 21C5 ED92 F075 C553 64AC 7123',
                               ipv6='[2001:678:558:1000::244]:443'),
            DirectoryAuthority('maatuska', '171.25.193.9:443', 80, '49015F787433103580E3B66A1707A00E60F2D15B',
                               'BD6A 8292 55CB 08E6 6FBE 7D37 4836 3586 E46B 3810',
                               ipv6='[2001:67c:289c::9]:80'),
            DirectoryAuthority('Faravahar', '154.35.175.225:80', 443, 'EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97',
                               'CF6D 0AAF B385 BE71 B8E1 11FC 5CFF 4B47 9237 33BC'),
            DirectoryAuthority('longclaw', '199.58.81.140:80', 443, '23D15D965BC35114467363C165C4F724B64B4F66',
                               '74A9 1064 6BCE EFBC D2E8 74FC 1DC9 9743 0F96 8145'),
            DirectoryAuthority('bastet', '204.13.164.118:80', 443, '27102BC123E7AF1D4741AE047E160C91ADC76B21',
                               '24E2 F139 121D 4394 C54B 5BCC 368B 3B41 1857 C413',
                               ipv6='[2620:13:4000:6000::1000:118]:443'),
        ]

    def get_random(self):
        """
        Return random directory authority.

        :rtype: DirectoryAuthority
        """
        return random.choice(self._directory_authorities)


class TorConsensus:
    def __init__(self, authorities=None, cache_storage=None):
        self._lock = Lock()
        self._authorities = authorities or DirectoryAuthoritiesList()
        self._cache_storage = cache_storage or TorCacheDirStorage()
        self._document = self._cache_storage.load_document(NetworkStatusDocument)
        if self._document:
            self._document.link_consensus(self)
        self.renew()

    @property
    def document(self):
        self.renew()
        return self._document

    @retry(3, Exception, log_func=functools.partial(log_retry, msg='Retry with another authority...'))
    def renew(self, force=False):
        with self._lock:
            if not force and self._document and self._document.is_fresh:
                return

            # tor ref: networkstatus_set_current_consensus
            authority = self._authorities.get_random()
            logger.info('Downloading new consensus from %s authority', authority.name)
            prev_hash = self._document.digest_sha3_256.hex() if self._document else None
            raw_string = authority.download('consensus', prev_hash=prev_hash)

            # Make sure it's parseable
            new_doc = TorDocumentsFactory.parse(raw_string,
                                                possible=(NetworkStatusDocument, NetworkStatusDiffDocument))
            if new_doc is None:
                raise Exception('Unknown document has been received')

            if type(new_doc) is NetworkStatusDiffDocument:
                new_doc = self._document.apply_diff(new_doc)

            new_doc.link_consensus(self)

            # TODO: Make sure it's signed enough
            # tor ref: networkstatus_check_consensus_signature
            # ...

            # Use new consensus document
            self._document = new_doc
            self._cache_storage.save_document(new_doc)

    def get_router(self, fingerprint):
        # TODO: make mapping with fingerprint as key?
        fingerprint_b = b32decode(fingerprint.upper())
        return next(
            onion_router for onion_router in self.document.routers if onion_router.fingerprint == fingerprint_b)

    def get_routers(self, flags=None, has_dir_port=True):
        """
        Select consensus routers that satisfy certain parameters.

        :param flags: Router flags
        :param has_dir_port: Has dir port
        :return: return list of routers
        """
        results = []

        for onion_router in self.document.routers:
            if flags and not all(f in onion_router.flags for f in flags):
                continue
            if has_dir_port and not onion_router.dir_port:
                continue
            results.append(onion_router)

        return results

    def get_random_router(self, flags=None, has_dir_port=None):
        """
        Select a random consensus router that satisfy certain parameters.

        :param flags: Router flags
        :param has_dir_port: Has dir port
        :return: router
        """
        routers = self.get_routers(flags, has_dir_port)
        return random.choice(routers)

    def get_random_guard_node(self, different_flags=None):
        flags = different_flags or [RouterFlags.Guard]
        return self.get_random_router(flags)

    def get_random_exit_node(self):
        flags = [RouterFlags.Fast, RouterFlags.Running, RouterFlags.Valid, RouterFlags.Exit]
        return self.get_random_router(flags)

    def get_random_middle_node(self):
        flags = [RouterFlags.Fast, RouterFlags.Running, RouterFlags.Valid]
        return self.get_random_router(flags)

    def get_hsdirs(self):
        flags = [RouterFlags.HSDir]
        return self.get_routers(flags, has_dir_port=True)

    @retry(5, BaseException, log_func=functools.partial(log_retry, msg='Retry with another router...'))
    def get_descriptor(self, fingerprint):
        """
        Get router descriptor by its fingerprint through randomly selected router.

        :param fingerprint:
        :return:
        """
        descriptor_provider = self.get_random_router(has_dir_port=True)
        return descriptor_provider.get_descriptor_for(fingerprint)

    def get_responsibles(self, hidden_service):
        """
        Get responsible dir for hidden service specified.

        :param hidden_service:
        :return:
        """
        hsdir_router_list = self.get_hsdirs()

        # Search for the 2 sets of 3 hidden service directories.
        for replica in range(2):
            descriptor_id = hidden_service.get_descriptor_id(replica)
            for i, dir in enumerate(hsdir_router_list):
                if dir.fingerprint > descriptor_id:
                    for j in range(3):
                        idx = (i + 1 + j) % len(hsdir_router_list)
                        yield hsdir_router_list[idx]
                    break
