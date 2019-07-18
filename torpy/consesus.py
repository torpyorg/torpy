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

from datetime import datetime
from base64 import b32decode, b64decode

import requests

from torpy.utils import retry, log_retry
from torpy.router import OnionRouter, RouterFlags
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
        """
        :return: Nickname of this authority
        """
        return self._name

    @property
    def consensus_url(self):
        """
        :return: Consensus url of this authority
        """
        return 'http://{}/tor/status-vote/current/consensus'.format(self._address)

    def download_consensus(self):
        """
        Download consensus from this authority. Can raise exceptions if authority not available
        :return: Consensus text
        """
        return requests.get(self.consensus_url, timeout=10).text


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
        :return: A random directory authority.
        :rtype: DirectoryAuthority
        """
        return random.choice(self._directory_authorities)


class TorConsensusDocument:
    def __init__(self, routers_list, voters, valid_after, fresh_until, valid_until):
        self._routers_list = routers_list
        self._voters = voters
        self._valid_after = valid_after
        self._fresh_until = fresh_until
        self._valid_until = valid_until

    @classmethod
    def from_raw_string(cls, raw_consensus, link_consensus=None):
        parser = TorConsensusParser()
        results_list, voters_list, valid_after, fresh_until, valid_until = parser.parse(raw_consensus, link_consensus)
        return cls(results_list, voters_list, valid_after, fresh_until, valid_until)

    @property
    def routers_list(self):
        return self._routers_list

    @property
    def is_fresh(self):
        # TODO: check fresh_until/valid_until
        return True


class TorConsensus:
    def __init__(self, directory_authorities=None):
        self._directory_authorities = directory_authorities or DirectoryAuthoritiesList()
        self._document = None
        self.renew()

    @retry(3, Exception, log_func=functools.partial(log_retry, msg='Retry with another authority...'))
    def renew(self, force=False):
        if not force and self._document and self._document.is_fresh:
            return

        # tor ref: networkstatus_set_current_consensus
        authority = self._directory_authorities.get_random()
        logger.info('Downloading new consensus from %s authority', authority.name)
        consensus_raw = authority.download_consensus()

        # Make sure it's parseable
        document = TorConsensusDocument.from_raw_string(consensus_raw, self)

        # TODO: Make sure it's signed enough
        # tor ref: networkstatus_check_consensus_signature
        # ...

        # Use new consensus document
        self._document = document

    def get_router(self, fingerprint):
        # TODO: make mapping with fingerprint as key?
        fingerprint_b = b32decode(fingerprint.upper())
        return next(
            onion_router for onion_router in self._document.routers_list if onion_router.fingerprint == fingerprint_b)

    def get_routers(self, flags=None, has_dir_port=True):
        """
        Select consensus routers that satisfy certain parameters
        :param flags: Router flags
        :param has_dir_port: Has dir port
        :return: return list of routers
        """
        results = []

        for onion_router in self._document.routers_list:
            if flags and not onion_router.flags.all_present(flags):
                continue
            if has_dir_port and not onion_router.dir_port:
                continue
            results.append(onion_router)

        return results

    def get_random_router(self, flags=None, has_dir_port=None):
        """
        Select a random consensus router that satisfy certain parameters
        :param flags: Router flags
        :param has_dir_port: Has dir port
        :return: router
        """
        routers = self.get_routers(flags, has_dir_port)
        return random.choice(routers)

    def get_random_guard_node(self, different_flags=None):
        flags = different_flags or [RouterFlags.guard]
        return self.get_random_router(flags)

    def get_random_exit_node(self):
        flags = [RouterFlags.fast, RouterFlags.running, RouterFlags.valid, RouterFlags.exit]
        return self.get_random_router(flags)

    def get_random_middle_node(self):
        flags = [RouterFlags.fast, RouterFlags.running, RouterFlags.valid]
        return self.get_random_router(flags)

    def get_hsdirs(self):
        flags = [RouterFlags.hsdir]
        return self.get_routers(flags, has_dir_port=True)

    @retry(5, BaseException, log_func=functools.partial(log_retry, msg='Retry with another router...'))
    def get_descriptor(self, fingerprint):
        """
        Get router descriptor by its fingerprint through randomly selected router
        :param fingerprint:
        :return:
        """
        descriptor_provider = self.get_random_router(has_dir_port=True)
        return descriptor_provider.get_descriptor_for(fingerprint)

    def get_responsibles(self, hidden_service):
        """
        rend-spec.txt
        1.4.
        At any time, there are 6 hidden service directories responsible for
        keeping replicas of a descriptor; they consist of 2 sets of 3 hidden
        service directories with consecutive onion IDs. Bob's OP learns about
        the complete list of hidden service directories by filtering the
        consensus status document received from the directory authorities. A
        hidden service directory is deemed responsible for a descriptor ID if
        it has the HSDir flag and its identity digest is one of the first three
        identity digests of HSDir relays following the descriptor ID in a
        circular list. A hidden service directory will only accept a descriptor
        whose timestamp is no more than three days before or one day after the
        current time according to the directory's clock.

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


class TorConsensusParser:
    def __init__(self, validate_flags=None):
        self.validate_flags = validate_flags or [RouterFlags.stable, RouterFlags.fast, RouterFlags.valid,
                                                 RouterFlags.running]

    @staticmethod
    def _parse_r_line(line):
        """
        Parse router info line
        :param line: the line
        :return: dict with router info
        """
        split_line = line.split(' ')

        nickname = split_line[1]
        fingerprint = split_line[2]
        ip = split_line[6]
        tor_port = int(split_line[7])
        dir_port = int(split_line[8])

        # The fingerprint is base64 encoded bytes.
        fingerprint += '=' * (-len(fingerprint) % 4)
        fingerprint = b64decode(fingerprint)

        return {'nickname': nickname, 'ip': ip, 'dir_port': dir_port, 'tor_port': tor_port, 'fingerprint': fingerprint}

    @staticmethod
    def _parse_s_line(line):
        flags = []
        for token in line.split(' '):
            if token == 's':
                continue
            flags.append(token.lower().replace('\n', '', 1))
        return flags

    @staticmethod
    def _parse_dir_line(line):
        #  dannenberg 0232AF901C31A04EE9848595AF9BB7620D4C5B2E dannenberg.torauth.de 193.23.244.244 80 443
        split_line = line.split(' ')[1:]
        fields = ['nickname', 'fingerprint', 'hostname', 'address', 'dir_port', 'or_port']
        return dict(zip(fields, split_line))

    @staticmethod
    def _to_flags(flags_list):
        flags = RouterFlags.unknown
        for f in RouterFlags:
            if f.name in flags_list:
                flags |= f
        return flags

    @staticmethod
    def _parse_date(date_str):
        # 2019-01-01 00:00:00
        return datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')

    def parse(self, consensus_string, link_consensus=None):
        results_list = []
        voters_list = []
        valid_after = fresh_until = valid_until = None

        router_info = None
        voter_info = None
        for line in consensus_string.splitlines():
            # Consensus info
            if line.startswith('valid-after '):
                valid_after = self._parse_date(line[12:])
            elif line.startswith('fresh-until '):
                fresh_until = self._parse_date(line[12:])
            elif line.startswith('valid-until '):
                valid_until = self._parse_date(line[12:])
            # Voters lines
            elif line.startswith('dir-source '):
                voter_info = self._parse_dir_line(line)
            elif line.startswith('contact '):
                voter_info['contact'] = line[8:]
            elif line.startswith('vote-digest '):
                voter_info['vote_digest'] = line[12:]
                voters_list.append(voter_info)
            # Router lines
            elif line.startswith('r '):
                router_info = self._parse_r_line(line)
            elif line.startswith('s '):
                assert router_info
                flags_list = self._parse_s_line(line)
                router_info['flags'] = self._to_flags(flags_list)
            elif line.startswith('v '):
                assert router_info
                assert router_info['flags']

                if router_info['flags'].all_present(self.validate_flags):
                    router_info['version'] = line[2:]

                    router = OnionRouter(**router_info, consensus=link_consensus)
                    results_list.append(router)
                router_info = None
            # Signatures lines
            elif line.startswith('directory-signature '):
                pass
            # TODO: calculate SHA1/SHA256

        return results_list, voters_list, valid_after, fresh_until, valid_until

