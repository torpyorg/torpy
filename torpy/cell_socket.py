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
import socket
import struct
import logging
import threading

from torpy.cells import TorCell, CellCerts, CellNetInfo, TorCommands, CellVersions, CellAuthChallenge
from torpy.utils import coro_recv_exact

logger = logging.getLogger(__name__)


class TorSocketConnectError(Exception):
    """Tor socket connection error."""


class TorCellSocket:
    """Handles communication with the relay."""

    RECV_BUFF_SIZE = 4094

    def __init__(self, router):
        self._router = router
        self._socket = None
        self._protocol = TorProtocol()
        self._our_public_ip = '0'
        self._send_close_lock = threading.Lock()

        self._cells_builder = self._cells_builder_gen()
        self._data = bytearray()
        self._next_len = None

    @property
    def ssl_socket(self):
        return self._socket

    def connect(self):
        if self._socket:
            raise Exception('Already connected')

        self._socket = ssl.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM), ssl_version=ssl.PROTOCOL_TLSv1_2
        )
        logger.debug('Connecting socket to %s relay...', self._router)
        try:
            self._socket.settimeout(15.0)
            self._socket.connect((self._router.ip, self._router.or_port))

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
        while self._socket:
            self._next_len = self._next_len or next(self._cells_builder)
            if len(self._data) < self._next_len:
                more_data = self._socket.recv(TorCellSocket.RECV_BUFF_SIZE)
                self._data.extend(more_data)

            for cell in self._build_next_cell():
                # Return first built cell
                return cell
            # Or read more data from socket

    def recv_cell_async(self):
        more_data = self._socket.recv(TorCellSocket.RECV_BUFF_SIZE)
        self._data.extend(more_data)
        self._next_len = self._next_len or next(self._cells_builder)
        yield from self._build_next_cell()

    def _build_next_cell(self):
        while len(self._data) >= self._next_len:
            send_buff = self._data[:self._next_len]
            self._data = self._data[self._next_len:]

            self._next_len = self._cells_builder.send(send_buff)
            if self._next_len is None:
                # New cell was built
                cell = next(self._cells_builder)
                yield cell
                self._next_len = next(self._cells_builder)
        logger.debug('Need more data (%i bytes, has %i bytes)', self._next_len, len(self._data))

    def _cells_builder_gen(self):
        while self._socket:
            circuit_id, command_num = yield from self._read_by_format(self._protocol.header_format)
            cell_type = TorCommands.get_by_num(command_num)
            payload = yield from self._read_command_payload(cell_type)
            # logger.debug("recv from socket: circuit_id = %x, command = %s,\n"
            #              "payload = %s", circuit_id, cell_type.__name__, to_hex(payload))
            cell = self._protocol.deserialize(cell_type, payload, circuit_id)
            yield None
            yield cell

    def _read_command_payload(self, cell_type):
        if cell_type.is_var_len():
            length, = yield from self._read_by_format(self._protocol.length_format)
        else:
            length = TorCell.MAX_PAYLOAD_SIZE
        cell_buff = yield from coro_recv_exact(length)
        return cell_buff

    def _read_by_format(self, struct_fmt):
        size = struct.calcsize(struct_fmt)
        data = yield from coro_recv_exact(size)
        if not data:
            raise NoDataException()
        return struct.unpack(struct_fmt, data)


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
        Send CellVersion.

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
        # Choose maximum supported by both
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
        logger.debug('Our public IP address: %s', cell.this_or)

    def _send_net_info(self):
        """If version 2 or higher is negotiated, each party sends the other a NETINFO cell."""
        logger.debug('Sending NET_INFO cell...')
        self.tor_socket.send_cell(CellNetInfo(int(time.time()), self.tor_socket.ip_address, '0'))
