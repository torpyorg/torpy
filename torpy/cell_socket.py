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

import ssl
import time
import struct
import socket
import logging
import threading

from torpy.cells import TorCell, TorCommands, CellCerts, CellVersions, CellAuthChallenge, CellNetInfo
from torpy.utils import to_hex, recv_exact

logger = logging.getLogger(__name__)


class TorSocketConnectError(Exception):
    """Tor socket connection error"""


class TorCellSocket:
    """Handles communication with the relay."""

    def __init__(self, router):
        self._router = router
        self._socket = None
        self._protocol = TorProtocol()
        self._our_public_ip = '0'
        self._send_close_lock = threading.Lock()

    def connect(self):
        if self._socket:
            raise Exception('Already connected')

        self._socket = ssl.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            ssl_version=ssl.PROTOCOL_TLSv1_2
        )
        logger.debug('Connecting socket to %s relay...', self._router)
        try:
            self._socket.settimeout(10.0)
            self._socket.connect((self._router.ip, self._router.tor_port))
            # For non block _recv_loop
            self._socket.settimeout(1.0)

            handshake = TorHandshake(self, self._protocol)
            handshake.initiate()
        except Exception as e:
            logger.error(e)
            raise TorSocketConnectError(e)

    @property
    def ip_address(self):
        return self._router.ip

    def close(self):
        logger.debug('Close TorCellSocket to %s relay...', self._router)
        with self._send_close_lock:
            self._socket.close()
            self._socket = None

    def send_cell(self, cell):
        logger.debug('Cell send: %r', cell)
        buffer = self._protocol.serialize(cell)
        with self._send_close_lock:
            # verbose: logger.debug('send to socket: %s', to_hex(buffer))
            if self._socket:
                self._socket.write(buffer)
            else:
                logger.warning('socket already closed')

    def recv_cell(self):
        circuit_id, command_num = self._read_by_format(self._protocol.header_format)
        cell_type = TorCommands.get_by_num(command_num)
        payload = self._read_command_payload(cell_type)
        # logger.debug("recv from socket: circuit_id = %x, command = %s,\n"
        #             "payload = %s", circuit_id, cell_type.__name__, to_hex(payload))
        return self._protocol.deserialize(cell_type, payload, circuit_id)

    def parse_buffer(self, payload_buffer):
        size = struct.calcsize(self._protocol.header_format)
        circuit_id, command_num = struct.unpack(self._protocol.header_format, payload_buffer[:size])
        cell_type = TorCommands.get_by_num(command_num)
        return self._protocol.deserialize(cell_type, payload_buffer[size:], circuit_id)

    def _read_command_payload(self, cell_type):
        if cell_type.is_var_len():
            length, = self._read_by_format(self._protocol.length_format)
        else:
            # TODO: MAX_PAYLOAD_SIZE = 509
            length = 509
        # TODO: use select?
        return recv_exact(self._socket, length)

    def _read_by_format(self, format):
        size = struct.calcsize(format)
        data = recv_exact(self._socket, size)
        if not data:
            raise NoDataException()
        return struct.unpack(format, data)


class NoDataException(Exception):
    pass


class TorProtocol:
    DEFAULT_VERSION = 3
    SUPPORTED_VERSION = [3, 4]

    def __init__(self, version=DEFAULT_VERSION):
        self._version = version

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, version):
        self._version = version

    @property
    def header_format(self):
        #    CircuitID                          [CIRCUIT_ID_LEN octets]
        #    Command                            [1 byte]
        if self.version < 4:
            return '!HB'
        else:
            # Link protocol 4 increases circuit ID width to 4 bytes.
            return '!IB'

    @property
    def length_format(self):
        #    Length                             [2 octets; big-endian integer]
        return '!H'

    def deserialize(self, command, payload, circuit_id=0):
        # parse depending on version
        # ...
        return TorCell.deserialize(command, circuit_id, payload, self.version)

    def serialize(self, cell):
        # get bytes depending on version
        # ...
        return cell.serialize(self.version)


class TorHandshake:
    def __init__(self, tor_socket, tor_protocol):
        self.tor_socket = tor_socket
        self.tor_protocol = tor_protocol

    def initiate(self):
        # When the in-protocol handshake is used, the initiator sends a
        # VERSIONS cell to indicate that it will not be renegotiating.  The
        # responder sends a VERSIONS cell, a CERTS cell (4.2 below) to give the
        # initiator the certificates it needs to learn the responder's
        # identity, an AUTH_CHALLENGE cell (4.3) that the initiator must include
        # as part of its answer if it chooses to authenticate, and a NET_INFO
        # cell (4.5).  As soon as it gets the CERTS cell, the initiator knows
        # whether the responder is correctly authenticated.  At this point the
        # initiator behaves differently depending on whether it wants to
        # authenticate or not. If it does not want to authenticate, it MUST
        # send a NET_INFO cell.
        self._send_versions()
        self.tor_protocol.version = self._retrieve_versions()

        self._retrieve_certs()

        self._retrieve_net_info()
        self._send_net_info()

    def _send_versions(self):
        """
        When the "in-protocol" handshake is used, implementations MUST NOT
        list any version before 3, and SHOULD list at least version 3.

        Link protocols differences are:
          1 -- The "certs up front" handshake.
          2 -- Uses the renegotiation-based handshake. Introduces
               variable-length cells.
          3 -- Uses the in-protocol handshake.
          4 -- Increases circuit ID width to 4 bytes.
          5 -- Adds support for link padding and negotiation (padding-spec.txt).
        """
        self.tor_socket.send_cell(CellVersions(self.tor_protocol.SUPPORTED_VERSION))

    def _retrieve_versions(self):
        cell = self.tor_socket.recv_cell()
        assert isinstance(cell, CellVersions)

        logger.debug('Remote protocol versions: %s', cell.versions)
        # if not any(link_ver in self._protocol_versions for link_ver in versions_cell.payload["versions"]):
        #    raise Exception("Not supported our version")
        # self._protocol_versions = versions_cell.payload["versions"]
        #if 4 in cell.versions:
        #    self._protocol_versions.append(4)

        # choose maximum supported by both
        return min(max(self.tor_protocol.SUPPORTED_VERSION), max(cell.versions))

    def _retrieve_certs(self):
        logger.debug('Retrieving CERTS cell...')
        cell_certs = self.tor_socket.recv_cell()
        assert isinstance(cell_certs, CellCerts)
        # TODO: check certs validity

        logger.debug('Retrieving AUTH_CHALLENGE cell...')
        cell_auth = self.tor_socket.recv_cell()
        assert isinstance(cell_auth, CellAuthChallenge)

    def _retrieve_net_info(self):
        logger.debug('Retrieving NET_INFO cell...')
        cell = self.tor_socket.recv_cell()
        assert isinstance(cell, CellNetInfo)
        # self._our_public_ip = cell.payload["our_address"]
        logger.debug('Our public IP address: %s', cell.this_or)

    def _send_net_info(self):
        """
        If version 2 or higher is negotiated, each party sends the other a NETINFO cell.
        """
        logger.debug('Sending NET_INFO cell...')
        self.tor_socket.send_cell(CellNetInfo(int(time.time()), self.tor_socket.ip_address, '0'))
