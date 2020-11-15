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

import socket
import struct
import logging
from enum import IntEnum, unique

from torpy.utils import AuthType, to_hex, fp_to_str
from torpy.crypto import TOR_DIGEST_LEN, hybrid_encrypt
from torpy.crypto_common import sha1

logger = logging.getLogger(__name__)


class TorCell:
    NUM = -1

    MAX_PAYLOAD_SIZE = 509

    def __init__(self, circuit_id=0):
        self.circuit_id = circuit_id

    @classmethod
    def is_var_len(cls):
        """
        If current cell variable-length.

        On a version 2 connection, variable-length cells are indicated by a
        command byte equal to 7 ("VERSIONS").
        On a version 3 or higher connection, variable-length cells are indicated by a command
        byte equal to 7 ("VERSIONS"), or greater than or equal to 128.

        See tor-spec.txt 3. "Cell Packet format"
        """
        if cls.NUM == CellVersions.NUM or cls.NUM >= 128:
            return True
        else:
            return False

    def _serialize_payload(self):
        raise NotImplementedError('Must be implemented in a subclass')

    def serialize(self, proto_version):
        payload = self._serialize_payload()

        # Link protocol 4 increases circuit ID width to 4 bytes.
        if proto_version < 4:
            buffer = struct.pack('!HB', self.circuit_id, self.NUM)
        else:
            buffer = struct.pack('!IB', self.circuit_id, self.NUM)

        if self.is_var_len():
            buffer += struct.pack('!H', len(payload)) + payload
        else:
            buffer += struct.pack('!509s', payload)

        return buffer

    @staticmethod
    def deserialize(cell_type, circuit_id, payload, proto_version):
        kwargs = cell_type._deserialize_payload(payload, proto_version)
        return cell_type(**kwargs, circuit_id=circuit_id)

    def _args_str(self):
        return ''

    def __repr__(self):
        """Represent TorCell string."""
        args = self._args_str()
        circ_str = 'circuit_id = {:x}'.format(self.circuit_id) if self.circuit_id else ''
        return '{}({}{})'.format(type(self).__name__, args, ', ' + circ_str if args and circ_str else circ_str)


class TorCellEmpty(TorCell):
    NUM = -1

    def __init__(self, data=None, circuit_id=0):
        super().__init__(circuit_id)
        self._data = data or b''
        if len(self._data) > 0:
            logger.warning('%s has some unnecessary data: %r', self.__class__.__qualname__, self._data)

    def _serialize_payload(self):
        return self._data

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        return {'data': payload}


class CellVersions(TorCell):
    """The payload in a VERSIONS cell is a series of big-endian two-byte integers."""

    NUM = 7

    def __init__(self, versions, circuit_id=0):
        super().__init__(circuit_id)
        self.versions = versions

    def _serialize_payload(self):
        return struct.pack('!' + ('H' * len(self.versions)), *self.versions)

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        versions = []
        while payload:
            versions.append(struct.unpack('!H', payload[:2])[0])
            payload = payload[2:]
        return {'versions': versions}

    def _args_str(self):
        return 'versions = {!r}'.format(self.versions)


class CellNetInfo(TorCell):
    """
    CellNetInfo representation.

    The cell's payload is:

    - Timestamp              [4 bytes]
    - Other OR's address     [variable]
    - Number of addresses    [1 byte]
    - This OR's addresses    [variable]

    Address format:

    - Type   (1 octet)
    - Length (1 octet)
    - Value  (variable-width)
    "Length" is the length of the Value field.
    "Type" is one of:
    - 0x00 -- Hostname
    - 0x04 -- IPv4 address
    - 0x06 -- IPv6 address
    - 0xF0 -- Error, transient
    - 0xF1 -- Error, nontransient
    """

    NUM = 8

    def __init__(self, timestamp, other_or, this_or, circuit_id=0):
        super().__init__(circuit_id)
        self.timestamp = timestamp
        self.other_or = other_or
        self.this_or = this_or

    def _serialize_payload(self):
        payload_bytes = struct.pack('!IBB', self.timestamp, 4, 4) + socket.inet_aton(self.other_or)
        payload_bytes += struct.pack('!BBB', 1, 4, 4) + socket.inet_aton(self.this_or)
        return payload_bytes

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        our_address_length = int(struct.unpack('!B', payload[5:][:1])[0])
        our_address = socket.inet_ntoa(payload[6:][:our_address_length])
        return {'timestamp': '', 'other_or': '', 'this_or': our_address}

    def _args_str(self):
        return 'timestamp = {!r}, other_or = {!r}, this_or = {!r}'.format(self.timestamp, self.other_or, self.this_or)


class CellDestroy(TorCell):
    """
    CellDestroy representation.

    The payload of a RELAY_TRUNCATED or DESTROY cell contains a single octet,
    describing why the circuit is being closed or truncated.
    """

    NUM = 4

    def __init__(self, reason, circuit_id):
        assert isinstance(reason, CircuitReason), 'reason must be CircuitReason enum'
        super().__init__(circuit_id)
        self.reason = reason

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        return {'reason': CircuitReason(struct.unpack('!B', payload[:1])[0])}

    def _serialize_payload(self):
        return struct.pack('!B', self.reason)

    def _args_str(self):
        return 'reason = {}'.format(self.reason.name)


class RelayedTorCell(TorCell):
    NUM = -1
    MAX_PAYLOD_SIZE = 509 - 11

    def __init__(self, inner_cell, stream_id, circuit_id, padding=None, encrypted=None):
        super().__init__(circuit_id)
        self._set_inits(inner_cell, padding, stream_id, None)
        self._encrypted = encrypted
        self._checked = False

    def _set_inits(self, inner_cell, padding, stream_id, digest, **kwargs):
        self._inner_cell = inner_cell
        self._padding = padding or b''
        # if self._padding:
        #    logger.warn('Has some padding!!!')
        self._stream_id = stream_id
        self._digest = digest

    @property
    def digest(self):
        return self._digest

    @property
    def stream_id(self):
        return self._stream_id

    @property
    def is_encrypted(self):
        return self._encrypted is not None

    def get_decrypted(self):
        assert self._checked
        return self._inner_cell

    def prepare(self, digesting_func):
        assert not self.digest, 'already prepared'

        payload = self._serialize_payload()
        self._digest = digesting_func(payload)
        assert len(self.digest) == 4

    def encrypt(self, encrypting_func):
        assert self._digest, 'must be prepared already'

        payload = self._serialize_payload()
        # verbose: logger.debug('relay full cell: %s', to_hex(payload))
        self._encrypted = encrypting_func(payload)

    def _serialize_payload(self):
        if self.is_encrypted:
            return self._encrypted
        else:
            relay_payload = self._inner_cell._serialize_payload()
            # logger.debug('relay_payload: %s', to_hex(relay_payload))

            payload_bytes = struct.pack('!B', self._inner_cell.NUM)
            payload_bytes += struct.pack('!H', 0)  # 'recognized'
            payload_bytes += struct.pack('!H', self._stream_id)
            payload_bytes += struct.pack('!4s', self._digest if self._digest else b'\x00' * 4)  # Digest placeholder
            if len(relay_payload) > RelayedTorCell.MAX_PAYLOD_SIZE:
                raise Exception(
                    'relay payload length cannot be more than {} ({} got)'.format(
                        RelayedTorCell.MAX_PAYLOD_SIZE, len(relay_payload)
                    )
                )
            assert len(relay_payload) + len(self._padding) <= RelayedTorCell.MAX_PAYLOD_SIZE, 'wrong relay payload size'
            payload_bytes += struct.pack('!H', len(relay_payload))
            payload_bytes += struct.pack('!{}s'.format(RelayedTorCell.MAX_PAYLOD_SIZE), relay_payload + self._padding)
            return payload_bytes

    def get_encrypted(self):
        assert self._inner_cell is None
        assert self._encrypted
        return self._encrypted

    def set_encrypted(self, new_encrypted):
        assert new_encrypted
        self._encrypted = new_encrypted

    @staticmethod
    def parse_header(payload):
        try:
            header = struct.unpack('!BHH4sH498s', payload)
            fields = ['cell_num', 'is_recognized', 'stream_id', 'digest', 'relay_payload_len', 'relay_payload_raw']
            return dict(zip(fields, header))
        except struct.error:
            logger.error("Can't unpack: %r", to_hex(payload))
            raise

    @staticmethod
    def set_header_digest(payload, new_digest):
        assert len(new_digest) == 4, 'digest must be 4 bytes'
        return payload[:5] + new_digest + payload[5 + 4:]

    def set_decrypted(self, cell_num, stream_id, digest, relay_payload_len, relay_payload_raw, **kwargs):
        relay_payload = relay_payload_raw[:relay_payload_len]
        padding = relay_payload_raw[relay_payload_len:]
        if all([b == 0 for b in padding]):
            padding = b''

        try:
            cell_type = TorCommands.get_relay_by_num(cell_num)
            logger.debug('Deserialize %s relay cell', cell_type.__name__)
            inner_cell = TorCell.deserialize(cell_type, 0, relay_payload, 0)
        except BaseException:
            logger.error("Can't deserialize %i cell: %r", cell_num, to_hex(relay_payload))
            raise

        self._set_inits(inner_cell, padding, stream_id, digest)
        self._encrypted = None
        self._checked = True

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        raise NotImplementedError("RelayedTorCell couldn't be deserialized")

    def _args_str(self):
        inner_str = '<encrypted>' if self.is_encrypted and not self._inner_cell else self._inner_cell
        stream_str = ', stream_id = {}'.format(self._stream_id or 0) if self._stream_id else ''
        digest_str = ', digest = {!r}'.format(self._digest) if self._digest else ''
        return 'inner_cell = {!r}{}{}'.format(inner_str, stream_str, digest_str)


class CellRelayEarly(RelayedTorCell):
    NUM = 9

    def __init__(self, inner_cell, stream_id=0, circuit_id=0, padding=None, encrypted=None):
        super().__init__(inner_cell, stream_id, circuit_id, padding=padding, encrypted=encrypted)


class CellPadding(TorCellEmpty):
    NUM = 0


class CellRelay(RelayedTorCell):
    NUM = 3

    def __init__(self, inner_cell, stream_id=0, circuit_id=0, padding=None, encrypted=None):
        super().__init__(inner_cell, stream_id, circuit_id, padding=padding, encrypted=encrypted)

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        return {'inner_cell': None, 'encrypted': payload}


class CellRelayExtend2(TorCell):
    """
    CellRelayExtend2 representation.

    To extend an existing circuit, the client sends an EXTEND2
    relay cell to the last node in the circuit.

    An EXTEND2 cell's relay payload contains:
        NSPEC      (Number of link specifiers)     [1 byte]
          NSPEC times:
            LSTYPE (Link specifier type)           [1 byte]
            LSLEN  (Link specifier length)         [1 byte]
            LSPEC  (Link specifier)                [LSLEN bytes]
        HTYPE      (Client Handshake Type)         [2 bytes]
        HLEN       (Client Handshake Data Len)     [2 bytes]
        HDATA      (Client Handshake Data)         [HLEN bytes]
    """

    NUM = 14

    def __init__(self, ip, port, fingerprint, skin):
        super().__init__()
        self.nspec = 2  # 2x NSPEC
        self.link_type = 0  # link_specifier_type::ipv4
        self.finger_type = 2  # link_specifier_type::legacy_id
        self.ip = ip
        self.port = port
        self.fingerprint = fingerprint
        self.skin = skin

    def _serialize_payload(self):
        payload_bytes = struct.pack('!B', self.nspec)
        ip_port_len = 6
        payload_bytes += struct.pack('!BB4sH', self.link_type, ip_port_len, socket.inet_aton(self.ip), self.port)

        assert len(self.fingerprint) == 20
        payload_bytes += struct.pack('!BB20s', self.finger_type, len(self.fingerprint), self.fingerprint)

        assert len(self.skin) == 84
        payload_bytes += struct.pack('!HH', 2, len(self.skin)) + self.skin
        return payload_bytes

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        raise NotImplementedError('CellRelayExtend2 deserialization not implemented')

    def _args_str(self):
        return 'ip = {}, port = {}, fingerprint = {}'.format(self.ip, self.port, fp_to_str(self.fingerprint))


class CellCreate(TorCell):
    NUM = 1

    def __init__(self, onion_skin, circuit_id):
        super().__init__(circuit_id)
        self.onion_skin = onion_skin

    def _serialize_payload(self):
        return self.onion_skin

    def _args_str(self):
        return "onion_skin = b'...'"


class CellCreateFast(CellCreate):
    NUM = 5


class CellCreate2(TorCell):
    NUM = 10

    def __init__(self, handshake_type, onion_skin, circuit_id):
        super().__init__(circuit_id)
        self.handshake_type = handshake_type
        self.onion_skin = onion_skin

    def _serialize_payload(self):
        return struct.pack('!HH', self.handshake_type, len(self.onion_skin)) + self.onion_skin

    def _args_str(self):
        return "type = {!r}, onion_skin = b'...'".format(self.handshake_type)


class CellCreated2(TorCell):
    """
    CellCreated2 representation.

    A CREATED2 cell contains:
        DATA_LEN      (Server Handshake Data Len) [2 bytes]
        DATA          (Server Handshake Data)     [DATA_LEN bytes]
    """

    NUM = 11

    def __init__(self, handshake_data, circuit_id):
        super().__init__(circuit_id)
        self.handshake_data = handshake_data

    def _serialize_payload(self):
        return struct.pack('!H', len(self.handshake_data)) + self.handshake_data

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        # tor ref: created_cell_parse
        length = struct.unpack('!H', payload[:2])[0]
        handshake_data = payload[2:length + 2]
        return {'handshake_data': handshake_data}

    def _args_str(self):
        return 'handshake_data = ...'


class CellCreatedFast(TorCell):
    NUM = 6

    def __init__(self, handshake_data, circuit_id):
        super().__init__(circuit_id)
        assert len(handshake_data) == TOR_DIGEST_LEN * 2
        self.handshake_data = handshake_data

    def _serialize_payload(self):
        return self.handshake_data

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        # tor ref: created_cell_parse
        return {'handshake_data': payload[:TOR_DIGEST_LEN * 2]}

    def _args_str(self):
        return 'handshake_data = ...'


class CellRelayBegin(TorCell):
    """
    CellRelayBegin representation.

    tor-spec.txt
    6.2.

    ADDRPORT [nul-terminated string]
    FLAGS[4 bytes]

    ADDRPORT is made of ADDRESS | ':' | PORT | [00]
    """

    NUM = 1

    def __init__(self, address, port):
        super().__init__()
        self.address = address
        self.flags = None
        self.port = port

    def _serialize_payload(self):
        addr_port = '{}:{}'.format(self.address, self.port).encode()
        return addr_port + struct.pack('!BI', 0, 0)

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        raise NotImplementedError('CellRelayBegin deserialization not implemented')

    def _args_str(self):
        return 'address = {!r}, port = {!r}, flags = {!r}'.format(self.address, self.port, self.flags)


class CellRelayBeginDir(TorCellEmpty):
    NUM = 13


class CellRelayData(TorCell):
    NUM = 2

    def __init__(self, data, circuit_id):
        super().__init__(circuit_id)
        self.data = data

    def _serialize_payload(self):
        return self.data

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        return {'data': payload}

    def _args_str(self):
        return 'data = ... ({} bytes)'.format(len(self.data))


class CellRelayEnd(TorCell):
    """
    CellRelayEnd representation.

    The payload of a RELAY_END cell begins with a single 'reason' byte to
    describe why the stream is closing.  For some reasons, it contains
    additional data (depending on the reason.)

    (With REASON_EXITPOLICY, the 4-byte IPv4 address or 16-byte IPv6 address
    forms the optional data, along with a 4-byte TTL; no other reason
    currently has extra data.)
    """

    NUM = 3

    def __init__(self, reason, circuit_id, address=None, ttl=None):
        assert isinstance(reason, StreamReason), 'reason must be StreamReason enum'
        super().__init__(circuit_id)
        self.reason = reason
        self.address = address
        self.ttl = ttl

    def _serialize_payload(self):
        if self.reason == StreamReason.EXIT_POLICY:
            ip_int = struct.unpack('!I', socket.inet_aton(self.address))[0]
            return struct.pack('!BII', self.reason, ip_int, self.ttl)
        else:
            return struct.pack('!B', self.reason)

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        payload_reason = payload[:1]
        reason = StreamReason(struct.unpack('!B', payload_reason)[0])
        ttl = None
        address = None
        if reason == StreamReason.EXIT_POLICY:
            # (With REASON_EXITPOLICY, the 4-byte IPv4 address or 16-byte IPv6 address
            # forms the optional data, along with a 4-byte TTL; no other reason
            # currently has extra data.)
            ip_int, ttl = struct.unpack('!II', payload[1:])
            address = socket.inet_ntoa(struct.pack('!I', ip_int))
        return {'reason': reason, 'address': address, 'ttl': ttl}

    def _args_str(self):
        return 'reason = {!r}'.format(self.reason.name)


class CellRelayConnected(TorCell):
    """
    CellRelayConnected representation.

    Otherwise, the exit node replies with a RELAY_CONNECTED cell, whose
    payload is in one of the following formats:
      The IPv4 address to which the connection was made [4 octets]
      A number of seconds (TTL) for which the address may be cached [4 octets]
    or
      Four zero-valued octets [4 octets]
      An address type (6)     [1 octet]
      The IPv6 address to which the connection was made [16 octets]
      A number of seconds (TTL) for which the address may be cached [4 octets]
    """

    NUM = 4

    def __init__(self, address, ttl, circuit_id):
        super().__init__(circuit_id)
        self.address = address
        self.ttl = ttl

    def _serialize_payload(self):
        if self.address and self.ttl:
            ip_int = struct.unpack('!I', socket.inet_aton(self.address))[0]
            return struct.pack('!II', ip_int, self.ttl)
        else:
            return b''

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        if payload:
            # logger.debug(to_hex(payload))
            ip_int, ttl = struct.unpack('!II', payload)
            address = socket.inet_ntoa(struct.pack('!I', ip_int))
            return {'address': address, 'ttl': ttl}
        else:
            # for dir begin?
            return {'address': '', 'ttl': 0}

    def _args_str(self):
        if self.address and self.ttl:
            return 'address = {}, ttl = {}'.format(self.address, self.ttl)
        else:
            return ''


class CellRelaySendMe(TorCell):
    NUM = 5

    def __init__(self, version=None, digest=None, circuit_id=0):
        super().__init__(circuit_id)
        self._version = version
        self._digest = digest

    def _serialize_payload(self):
        if self._version and self._digest:
            return struct.pack('!BH', self._version, len(self._digest)) + self._digest
        else:
            return b''

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        version = None
        digest = None
        if len(payload) > 0:
            version, data_len = struct.unpack('!BH', payload[:3])
            if version != 0 and version != 1:
                logger.error('wrong sendme call version')
            digest = payload[3:3 + data_len]
            if len(payload[3 + data_len:]) > 0:
                logger.error('has some extra data: %r', payload[3 + data_len:])
        return {'version': version, 'digest': digest}


class CellRelayTruncated(CellDestroy):
    NUM = 9


class CellRelayExtended2(CellCreated2):
    """The payload of an EXTENDED2 cell is the same as the payload of a CREATED2 cell."""

    NUM = 15


class CellRelayEstablishRendezvous(TorCell):
    NUM = 33

    def __init__(self, rendezvous_cookie, circuit_id):
        super().__init__(circuit_id)
        assert len(rendezvous_cookie) == 20
        self.rendezvous_cookie = rendezvous_cookie

    def _serialize_payload(self):
        return self.rendezvous_cookie

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        raise NotImplementedError('CellRelayEstablishRendezvous deserialization not implemented')


class CellRelayIntroduce1(TorCell):
    NUM = 34

    def __init__(
        self,
        introduction_point,
        introduction_point_key,
        introducee,
        rendezvous_cookie,
        auth_type,
        descriptor_cookie,
        circuit_id,
    ):
        super().__init__(circuit_id)
        self.introduction_point = introduction_point
        self.introduction_point_key = introduction_point_key
        self.handshake_encrypted = self._create_handshake(introducee, rendezvous_cookie, auth_type, descriptor_cookie)

    def _create_handshake(self, introducee, rendezvous_cookie, auth_type, descriptor_cookie):
        #
        # payload of the RELAY_COMMAND_INTRODUCE1
        # command:
        #
        # VER    Version byte: set to 2.        [1 octet]
        # IP     Rendezvous point's address    [4 octets]
        # PORT   Rendezvous point's OR port    [2 octets]
        # ID     Rendezvous point identity ID [20 octets]
        # KLEN   Length of onion key           [2 octets]
        # KEY    Rendezvous point onion key [KLEN octets]
        # RC     Rendezvous cookie            [20 octets]
        # g^x    Diffie-Hellman data, part 1 [128 octets]
        #

        #  VER    Version byte: set to 3.        [1 octet]
        #  AUTHT  The auth type that is used     [1 octet]
        #  If AUTHT != [00]:
        #      AUTHL  Length of auth data           [2 octets]
        #      AUTHD  Auth data                     [variable]
        #  TS     A timestamp                   [4 octets]
        #  IP     Rendezvous point's address    [4 octets]
        #  PORT   Rendezvous point's OR port    [2 octets]
        #  ID     Rendezvous point identity ID [20 octets]
        #  KLEN   Length of onion key           [2 octets]
        #  KEY    Rendezvous point onion key [KLEN octets]
        #  RC     Rendezvous cookie            [20 octets]
        #  g^x    Diffie-Hellman data, part 1 [128 octets]

        handshake = struct.pack('!BB', 3, auth_type)
        if auth_type != AuthType.No:
            assert len(descriptor_cookie) == 16
            handshake += struct.pack('!H16s', len(descriptor_cookie), descriptor_cookie)
        handshake += struct.pack('!I', 0)  # timestamp
        handshake += struct.pack('!4sH', socket.inet_aton(introducee.ip), introducee.or_port)
        assert len(introducee.fingerprint) == 20
        handshake += struct.pack('!20s', introducee.fingerprint)
        handshake += struct.pack('!H', len(introducee.descriptor.onion_key)) + introducee.descriptor.onion_key
        handshake += struct.pack('!20s', rendezvous_cookie)
        assert len(self.introduction_point_key) == 128
        handshake += self.introduction_point_key

        return hybrid_encrypt(handshake, self.introduction_point.service_key)

    def _serialize_payload(self):
        #  PK_ID  Identifier for Bob's PK      [20 octets]
        return struct.pack('!20s', sha1(self.introduction_point.service_key)) + self.handshake_encrypted

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        raise NotImplementedError('CellRelayEstablishRendezvous deserialization not implemented')


class CellRelayRendezvous2(TorCell):
    NUM = 37

    def __init__(self, handshake_data, circuit_id):
        super().__init__(circuit_id)
        self.handshake_data = handshake_data

    def _serialize_payload(self):
        return self.handshake_data

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        return {'handshake_data': payload}

    def _args_str(self):
        return 'handshake_data = ...'


class CellRelayRendezvousEstablished(TorCellEmpty):
    NUM = 39


class CellRelayIntroduceAck(TorCellEmpty):
    NUM = 40


class CellCerts(TorCell):
    NUM = 129

    def __init__(self, certs, circuit_id=0):
        super().__init__(circuit_id)
        self.certs = certs

    def _serialize_payload(self):
        raise NotImplementedError('CellCerts serialization not implemented')

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        # TODO: implement parse
        return {'certs': payload}


class CellAuthChallenge(TorCell):
    NUM = 130

    def __init__(self, auth, circuit_id=0):
        super().__init__(circuit_id)
        self.auth = auth

    def _serialize_payload(self):
        raise NotImplementedError('CellAuthChallenge serialization not implemented')

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        # TODO: implement parse
        return {'auth': payload}


class TorCommands:
    """
    Enum class which contains all available command types.

    tor-spec.txt 3. "Cell Packet format"
    """

    _map = {
        # fmt: off
        # Fixed-length command values.
        CellPadding.NUM: CellPadding,               # 0
        CellCreate.NUM: CellCreate,                 # 1
        # CellCreated.NUM: CellCreated,               # 2
        CellRelay.NUM: CellRelay,                   # 3
        CellDestroy.NUM: CellDestroy,               # 4
        CellCreateFast.NUM: CellCreateFast,         # 5
        CellCreatedFast.NUM: CellCreatedFast,       # 6
        CellNetInfo.NUM: CellNetInfo,               # 8
        CellRelayEarly.NUM: CellRelayEarly,         # 9
        CellCreate2.NUM: CellCreate2,               # 10
        CellCreated2.NUM: CellCreated2,             # 11

        # Variable-length command values.
        CellVersions.NUM: CellVersions,             # 7
        # CellVPadding.NUM: CellVPadding,            # 128
        CellCerts.NUM: CellCerts,                   # 129
        CellAuthChallenge.NUM: CellAuthChallenge,   # 130
        # CellAuthenticate.NUM: CellAuthenticate,    # 131
        # fmt: on
    }

    @classmethod
    def get_by_num(cls, num):
        cell_type = cls._map.get(num, None)
        if not cell_type:
            raise Exception('Cell type ({}) not found'.format(num))
        return cell_type

    # The relay commands.
    #
    # Within a circuit, the OP and the exit node use the contents of
    # RELAY packets to tunnel end-to-end commands and TCP connections
    # ("Streams") across circuits. End-to-end commands can be initiated
    # by either edge; streams are initiated by the OP.
    #
    _map2 = {
        # fmt: off
        CellRelayBegin.NUM: CellRelayBegin,            # 1
        CellRelayData.NUM: CellRelayData,              # 2
        CellRelayEnd.NUM: CellRelayEnd,                # 3
        CellRelayConnected.NUM: CellRelayConnected,    # 4
        CellRelaySendMe.NUM: CellRelaySendMe,          # 5
        # CellRelayExtend2.NUM: CellRelayExtend2,        # 6
        # CellRelayExtended2.NUM: CellRelayExtended2,    # 7
        # CellRelayTruncate.NUM: CellRelayTruncate,      # 8
        CellRelayTruncated.NUM: CellRelayTruncated,    # 9
        # CellRelayDrop.NUM: CellRelayDrop,             # 10
        # CellRelayResolve.NUM: CellRelayResolve,       # 11
        # CellRelayResolved.NUM: CellRelayResolved,     # 12
        CellRelayBeginDir.NUM: CellRelayBeginDir,      # 13
        # CellRelayExtend2.NUM: CellRelayExtend2,       # 14
        CellRelayExtended2.NUM: CellRelayExtended2,    # 15
        # ...
        CellRelayEstablishRendezvous.NUM: CellRelayEstablishRendezvous,         # 33
        CellRelayIntroduce1.NUM: CellRelayIntroduce1,                           # 34
        CellRelayRendezvous2.NUM: CellRelayRendezvous2,                         # 37
        # ...
        CellRelayRendezvousEstablished.NUM: CellRelayRendezvousEstablished,     # 39
        CellRelayIntroduceAck.NUM: CellRelayIntroduceAck,                       # 40
        # fmt: on
    }

    @classmethod
    def get_relay_by_num(cls, num):
        cell_type = cls._map2.get(num, None)
        if not cell_type:
            raise Exception('Cell type ({}) not found'.format(num))
        return cell_type


# fmt: off
@unique
class StreamReason(IntEnum):
    MISC = 1              # (catch-all for unlisted reasons)
    RESOLVE_FAILED = 2    # (couldn't look up hostname)
    CONNECT_REFUSED = 3   # (remote host refused connection) [*]
    EXIT_POLICY = 4       # (OR refuses to connect to host or port)
    DESTROY = 5           # (Circuit is being destroyed)
    DONE = 6              # (Anonymized TCP connection was closed)
    TIMEOUT = 7           # (Connection timed out, or OR timed out while connecting)
    NO_ROUTE = 8          # (Routing error while attempting to contact destination)
    HIBERNATING = 9       # (OR is temporarily hibernating)
    INTERNAL = 10         # (Internal error at the OR)
    RESOURCE_LIMIT = 11   # (OR has no resources to fulfill request)
    CONN_RESET = 12       # (Connection was unexpectedly reset)
    TOR_PROTOCOL = 13     # (Sent when closing connection because of Tor protocol violations.)
    NOT_DIRECTORY = 14    # (Client sent RELAY_BEGIN_DIR to a non-directory relay.)


@unique
class CircuitReason(IntEnum):
    NONE = 0              # (No reason given.)
    PROTOCOL = 1          # (Tor protocol violation.)
    INTERNAL = 2          # (Internal error.)
    REQUESTED = 3         # (A client sent a TRUNCATE command.)
    HIBERNATING = 4       # (Not currently operating; trying to save bandwidth.)
    RESOURCE_LIMIT = 5    # (Out of memory, sockets, or circuit IDs.)
    CONNECT_FAILED = 6    # (Unable to reach relay.)
    OR_IDENTITY = 7       # (Connected to relay, but its OR identity was not as expected.)
    OR_CONN_CLOSED = 8    # (The OR connection that was carrying this circuit died.)
    FINISHED = 9          # (The circuit has expired for being dirty or old.)
    TIMEOUT = 10          # (Circuit construction took too long)
    DESTROYED = 11        # (The circuit was destroyed w/o client TRUNCATE)
    NO_SUCH_SERVICE = 12  # (Request for unknown hidden service)
# fmt: on
