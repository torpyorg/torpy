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
from datetime import datetime, timedelta
from enum import unique, Enum, auto

from torpy.documents.basics import TorDocumentObject, TorDocument
from torpy.documents.items import ItemType, ItemParsers, Item, ItemObject, ItemDate, ItemInt, ItemEnum, ItemMulti
from torpy.crypto_common import sha3_256, b64decode
from torpy.utils import cached_property

logger = logging.getLogger(__name__)


class FetchDescriptorError(Exception):
    ...


class ItemSignature(ItemMulti):
    @staticmethod
    def _parse_args(line, *_):
        splits = line.split(' ')

        # [SP Algorithm] SP identity SP signing-key-digest
        if len(splits) == 2:
            return {'algorithm': 'sha1', 'identity': splits[0], 'signing_key_digest': splits[1]}
        else:
            return {'algorithm': splits[0], 'identity': splits[1], 'signing_key_digest': splits[2]}
        # The Algorithm is one of "sha1" or "sha256" if it is present;
        # implementations MUST ignore directory-signature entries with an
        # unrecognized Algorithm.  "sha1" is the default, if no Algorithm is
        # given.  The algorithm describes how to compute the hash of the
        # document before signing it.

    def __init__(self, keyword):
        super().__init__(
            keyword, 'signature', parse_func=ItemSignature._parse_args, out_name='signatures', as_list=True
        )


class DirSourceObject(TorDocumentObject):

    # [Exactly once, at start]
    # dir-source dannenberg 0232AF901C31A04EE9848595AF9BB7620D4C5B2E dannenberg.torauth.de 193.23.244.244 80 443
    START_ITEM = Item(
        'dir-source',
        parse_func=ItemParsers.split_symbol,
        parse_args=[' ', ['nickname', 'fingerprint', 'hostname', 'address', 'dir_port', 'or_port']],
    )

    ITEMS = [
        # "contact" SP string NL
        # [Exactly once.]
        # contact Andreas Lehner
        Item('contact'),
        # "vote-digest" SP digest NL
        # [Exactly once.]
        # vote-digest 8E4B75DC6EC0AB037A9D2C2C3EB46BBCDFDA17C4
        Item('vote-digest'),
    ]


def _parse_r_line(line, *_):
    """
    Parse router info line.

    :param line: the line
    :return: dict with router info
    """
    split_line = line.split(' ')
    return {
        'nickname': split_line[0],
        'fingerprint': split_line[1],
        'digest': split_line[2],
        'ip': split_line[5],
        'dir_port': int(split_line[7]),
        'or_port': int(split_line[6]),

    }


@unique
class RouterFlags(Enum):
    Unknown = 0

    #    "Stable" -- A router is 'Stable' if it is active, and either its Weighted
    #    MTBF is at least the median for known active routers or its Weighted MTBF
    #    corresponds to at least 7 days. Routers are never called Stable if they are
    #    running a version of Tor known to drop circuits stupidly.  (0.1.1.10-alpha
    #    through 0.1.1.16-rc are stupid this way.)
    Stable = auto()

    #    "Fast" -- A router is 'Fast' if it is active, and its bandwidth is either in
    #    the top 7/8ths for known active routers or at least 100KB/s.
    Fast = auto()

    #    "Valid" -- a router is 'Valid' if it is running a version of Tor not
    #    known to be broken, and the directory authority has not blacklisted
    #    it as suspicious.
    Valid = auto()

    #    "Running" -- A router is 'Running' if the authority managed to connect to
    #    it successfully within the last 45 minutes on all its published ORPorts.
    Running = auto()

    #    "Guard" -- A router is a possible Guard if all of the following apply:
    #        - It is Fast,
    #        - It is Stable,
    #        - Its Weighted Fractional Uptime is at least the median for "familiar"
    #          active routers,
    #        - It is "familiar",
    #        - Its bandwidth is at least AuthDirGuardBWGuarantee (if set, 2 MB by
    #          default), OR its bandwidth is among the 25% fastest relays,
    #        - It qualifies for the V2Dir flag as described below (this
    #          constraint was added in 0.3.3.x, because in 0.3.0.x clients
    #          started avoiding guards that didn't also have the V2Dir flag).
    Guard = auto()

    #    "Exit" -- A router is called an 'Exit' iff it allows exits to at
    #    least one /8 address space on each of ports 80 and 443. (Up until
    #    Tor version 0.3.2, the flag was assigned if relays exit to at least
    #    two of the ports 80, 443, and 6667.)
    Exit = auto()

    #    "HSDir" -- A router is a v2 hidden service directory if it stores and
    #    serves v2 hidden service descriptors, has the Stable and Fast flag, and the
    #    authority believes that it's been up for at least 96 hours (or the current
    #    value of MinUptimeHidServDirectoryV2).
    HSDir = auto()

    #    "V2Dir" -- A router supports the v2 directory protocol or higher if it has
    #    an open directory port OR a tunnelled-dir-server line in its router
    #    descriptor, and it is running a version of the directory
    #    protocol that supports the functionality clients need.  (Currently, every
    #    supported version of Tor supports the functionality that clients need,
    #    but some relays might set "DirCache 0" or set really low rate limiting,
    #    making them unqualified to be a directory mirror, i.e. they will omit
    #    the tunnelled-dir-server line from their descriptor.)
    V2Dir = auto()

    #    "Authority" -- A router is called an 'Authority' if the authority
    #    generating the network-status document believes it is an authority.
    Authority = auto()

    #    "StaleDesc" -- authorities should vote to assign this flag if the
    #    published time on the descriptor is over 18 hours in the past.  (This flag
    #    was added in 0.4.0.1-alpha.)
    StaleDesc = auto()

    def all_present(self, flags_list):
        return all(self & flag for flag in flags_list)


class Router:
    def __init__(self, nickname, fingerprint, ip, or_port, dir_port,
                 flags, version=None, digest=None, **kwargs):
        self._nickname = nickname
        if type(fingerprint) is not bytes:
            fingerprint = b64decode(fingerprint)
        self._fingerprint = fingerprint
        self._digest = b64decode(digest) if digest else None
        self._ip = ip
        self._or_port = or_port
        self._dir_port = dir_port
        self._version = version
        self._flags = flags

        self._consensus = None
        self._service_key = None

    @property
    def nickname(self):
        return self._nickname

    @property
    def fingerprint(self):
        return self._fingerprint

    @property
    def ip(self):
        return self._ip

    @property
    def or_port(self):
        return self._or_port

    @property
    def dir_port(self):
        return self._dir_port

    @property
    def flags(self):
        return self._flags

    @cached_property
    def descriptor(self):
        logger.info('Getting descriptor for %s...', self)
        return self._consensus.get_descriptor(self._fingerprint)

    @property
    def service_key(self):
        return self._service_key

    @service_key.setter
    def service_key(self, value):
        self._service_key = value

    def __str__(self):
        """Get router string representation."""
        s = f'{self._ip}:{self._or_port}'
        comm = '; '.join(filter(None, [self._nickname, self._version]))
        if RouterFlags.Authority in self._flags:
            s += ' authority'
        if comm:
            s += f' ({comm})'
        return s


class RouterObject(TorDocumentObject):
    CLASS = Router

    # "r" SP nickname SP identity SP digest SP publication SP IP SP ORPort SP DirPort NL
    # [At start, exactly once.]
    # r seele AAoQ1DAR6kkoo19hBAX5K0QztNw HVuAXf9AUKcwgmwTP4DI6xHhmeI 2019-07-20 13:33:25 67.174.243.193 9001 0
    START_ITEM = Item('r', parse_func=_parse_r_line)

    ITEMS = [
        # "a" SP address ":" port NL
        # [Any number]
        # ...
        Item('a', type=ItemType.AnyNumber),
        # "s" SP Flags NL
        # [Exactly once.]
        # s Running Stable V2Dir Valid
        ItemEnum('s', enum_cls=RouterFlags, out_name='flags'),
        # "v" SP version NL
        # [At most once.]
        # v Tor 0.3.5.8
        Item('v', out_name='version', type=ItemType.AtMostOnce),
        # "pr" SP Entries NL
        # [At most once.]
        # pr Cons=1-2 Desc=1-2 DirCache=1-2 HSDir=1-2 HSIntro=3-4 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 ...
        Item('pr', type=ItemType.AtMostOnce),
        # "w" SP "Bandwidth=" INT [SP "Measured=" INT] [SP "Unmeasured=1"] NL
        # [At most once.]
        # w Bandwidth=5
        Item('w', type=ItemType.AtMostOnce),
        # "p" SP ("accept" / "reject") SP PortList NL
        # [At most once.]
        # p reject 1-65535
        Item('p', type=ItemType.AtMostOnce),
    ]


class NetworkStatusDocument(TorDocument):
    DOCUMENT_NAME = 'network_status'

    # "network-status-version" SP version NL
    # [At start, exactly once.]
    # network-status-version 3
    START_ITEM = ItemInt('network-status-version')

    ITEMS = [
        # "vote-status" SP type NL
        # [Exactly once.]
        # vote-status consensus
        Item('vote-status'),
        # "consensus-method" SP Integer NL
        # [At most once for consensuses; does not occur in votes.]
        # [No extra arguments]
        # consensus-method 28
        ItemInt('consensus-method'),
        # "valid-after" SP YYYY-MM-DD SP HH:MM:SS NL
        # [Exactly once.]
        # valid-after 2019-07-20 21:00:00
        ItemDate('valid-after'),
        # "fresh-until" SP YYYY-MM-DD SP HH:MM:SS NL
        # [Exactly once.]
        # fresh-until 2019-07-20 22:00:00
        ItemDate('fresh-until'),
        # "valid-until" SP YYYY-MM-DD SP HH:MM:SS NL
        # [Exactly once.]
        # valid-until 2019-07-21 00:00:00
        ItemDate('valid-until'),
        # "voting-delay" SP VoteSeconds SP DistSeconds NL
        # [Exactly once.]
        # voting-delay 300 300
        Item('voting-delay'),
        # "client-versions" SP VersionList NL
        # [At most once.]
        # client-versions 0.2.9.16,0.2.9.17,0.3.5.7,0.3.5.8,0.4.0.5,0.4.0.6,0.4.1.2-alpha,0.4.1.3-alpha,0.4.1.4-rc
        Item('client-versions'),
        # "server-versions" SP VersionList NL
        # [At most once.]
        # server-versions 0.2.9.15,0.2.9.16,0.2.9.17,0.3.5.8,0.4.0.5,0.4.0.6,0.4.1.2-alpha,0.4.1.3-alpha,0.4.1.4-rc
        Item('server-versions'),
        # "package" SP PackageName SP Version SP URL SP DIGESTS NL
        # [Any number of times.]
        # Included in consensuses only for method 19 and later.
        # "known-flags" SP FlagList NL
        # [Exactly once.]
        # known-flags Authority BadExit Exit Fast Guard HSDir NoEdConsensus Running Stable StaleDesc V2Dir Valid
        Item('known-flags'),
        # "recommended-client-protocols" SP Entries NL
        # [At most once.]
        # recommended-client-protocols Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 Link=4 ...
        Item('recommended-client-protocols'),
        # "recommended-relay-protocols" SP Entries NL
        # [At most once.]
        # recommended-relay-protocols Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 Link=4 ...
        Item('recommended-relay-protocols'),
        # "required-client-protocols" SP Entries NL
        # [At most once.]
        # required-client-protocols Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 Link=4 ...`
        Item('required-client-protocols'),
        # "required-relay-protocols" SP Entries NL
        # [At most once.]
        # required-relay-protocols Cons=1 Desc=1 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 Link=3-4 ...
        Item('required-relay-protocols'),
        # "params" SP [Parameters] NL
        # [At most once]
        # params CircuitPriorityHalflifeMsec=30000 DoSCircuitCreationEnabled=1 DoSConnectionEnabled=1 ...
        Item('params'),
        # "shared-rand-previous-value" SP NumReveals SP Value NL
        # [At most once]
        # shared-rand-previous-value 9 ybFb42KVOFmJR/EMtjPJNJiTBDyiI0eefmebenN9EY0=
        Item('shared-rand-previous-value'),
        # "shared-rand-current-value" SP NumReveals SP Value NL
        # [At most once]
        # shared-rand-current-value 9 p4+CMGa6M7EhDqGNpofcJ2MeQ7f7qdF8QslK+AOnrQg=
        Item('shared-rand-current-value'),
        ItemObject(DirSourceObject, out_name='voters'),
        ItemObject(RouterObject, out_name='routers'),
        # "directory-signature" [SP Algorithm] SP identity SP signing-key-digest
        #         NL Signature
        ItemSignature('directory-signature'),
    ]

    def __init__(self, raw_string):
        super().__init__(
            raw_string,
            digests_names=['sha1', 'sha3_256'],
            digest_start='network-status-version',
            digest_end='directory-signature ',
        )

    def link_consensus(self, consensus):
        for router in self.routers:
            router._consensus = consensus

    @property
    def is_live(self):
        # tor ref: networkstatus_is_live
        return self.valid_after <= datetime.utcnow() <= self.valid_until

    @property
    def is_reasonably_live(self):
        # tor ref: networkstatus_consensus_reasonably_live
        return self.valid_after - timedelta(hours=24) <= datetime.utcnow() <= self.valid_until + timedelta(hours=24)

    @property
    def digest_sha1(self):
        return self.get_digest('sha1')

    @property
    def digest_sha3_256(self):
        return self.get_digest('sha3_256')

    def find_signature(self, identity):
        for sign in self.signatures:
            if sign['identity'] == identity:
                return sign

    def apply_diff(self, diff):
        logger.info('Apply network-status-diff for %s to %s', self.digest_sha3_256.hex(), diff.to_digest.lower())
        assert self.digest_sha3_256.hex() == diff.from_digest.lower()

        lines = self.raw_string.split('\n')
        cur_line = 1
        for action in diff.actions:
            cur_end = len(lines)
            cur_line = action.apply(lines, cur_line, cur_end)

        raw_string_new = '\n'.join(lines) + '\n'
        assert sha3_256(raw_string_new.encode()).hex() == diff.to_digest.lower()
        return NetworkStatusDocument(raw_string_new)
