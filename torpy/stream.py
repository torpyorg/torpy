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

import time
import socket
import logging
import threading
from enum import unique, Enum, auto
from selectors import EVENT_READ, DefaultSelector
from contextlib import contextmanager

from torpy.cells import (
    CellRelayEnd,
    StreamReason,
    CellRelayData,
    CellRelayBegin,
    RelayedTorCell,
    CellRelaySendMe,
    CellRelayBeginDir,
    CellRelayConnected,
)
from torpy.utils import chunks, hostname_key
from torpy.hiddenservice import HiddenService

logger = logging.getLogger(__name__)


class TorWindow:
    def __init__(self, start=1000, increment=100):
        self._lock = threading.Lock()
        self._deliver = self._package = self._start = start
        self._increment = increment

    def need_sendme(self):
        with self._lock:
            if self._deliver > (self._start - self._increment):
                return False

            self._deliver += self._increment
            return True

    def deliver_dec(self):
        with self._lock:
            self._deliver -= 1

    def package_dec(self):
        with self._lock:
            self._package -= 1

    def package_inc(self):
        with self._lock:
            self._package += self._increment


class TorSocketLoop(threading.Thread):
    def __init__(self, our_sock, send_func):
        super().__init__(name='SocketLoop{:x}'.format(our_sock.fileno()))
        self._our_sock = our_sock
        self._send_func = send_func
        self._do_loop = True

        self._cntrl_l = threading.Lock()
        self._cntrl_r, self._cntrl_w = socket.socketpair()

        self._selector = DefaultSelector()
        self._selector.register(self._our_sock, EVENT_READ, self._do_recv)
        self._selector.register(self._cntrl_r, EVENT_READ, self._do_stop)

    def _do_recv(self, sock):
        try:
            data = sock.recv(1024)
            self._send_func(data)
        except ConnectionResetError:
            logger.debug('Client was badly disconnected...')

    def _do_stop(self, sock):
        self._do_loop = False

    def _cleanup(self):
        with self._cntrl_l:
            logger.debug('Cleanup')
            self._selector.unregister(self._cntrl_r)
            self._cntrl_w.close()
            self._cntrl_r.close()
            self.close_sock()
            self._selector.close()

    @property
    def fileno(self):
        if not self._our_sock:
            return None
        return self._our_sock.fileno()

    def close_sock(self):
        if not self._our_sock:
            return
        self._selector.unregister(self._our_sock)
        self._our_sock.close()
        self._our_sock = None

    def stop(self):
        #  Because stop could be called twice
        with self._cntrl_l:
            logger.debug('Stopping...')
            self._cntrl_w.send(b'\1')

    def run(self):
        logger.debug('Starting...')
        while self._do_loop:
            events = self._selector.select()
            for key, _ in events:
                callback = key.data
                callback(key.fileobj)

        self._cleanup()
        logger.debug('Stopped!')

    def append(self, data):
        self._our_sock.send(data)


@unique
class StreamState(Enum):
    Connecting = auto()
    Connected = auto()
    Disconnected = auto()
    Closed = auto()


class TorStream:
    """This tor stream object implements socket-like interface."""

    def __init__(self, id, circuit, auth_data=None):
        logger.info('Stream #%i: creating attached to #%x circuit...', id, circuit.id)
        self._id = id
        self._circuit = circuit
        self._auth_data = auth_data or {}

        self._buffer = bytearray()
        self._data_lock = threading.Lock()
        self._has_data = threading.Event()
        self._received_callbacks = []

        self._conn_timeout = 30
        self._recv_timeout = 60

        self._state = StreamState.Closed
        self._close_lock = threading.Lock()

        self._window = TorWindow(start=500, increment=50)

        self._loop = None

    def __enter__(self):
        """Start using the stream."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Close the stream."""
        self.close()

    @property
    def id(self):
        return self._id

    @property
    def has_socket_loop(self):
        return self._loop is not None

    @property
    def state(self):
        return self._state

    def handle_cell(self, cell):
        logger.debug(cell)
        if isinstance(cell, CellRelayConnected):
            self._connected(cell)
        elif isinstance(cell, CellRelayEnd):
            self._end(cell)
            self._call_received()
        elif isinstance(cell, CellRelayData):
            self._append(cell.data)
            self._window.deliver_dec()
            if self._window.need_sendme():
                self.send_relay(CellRelaySendMe(circuit_id=cell.circuit_id))
            self._call_received()
        elif isinstance(cell, CellRelaySendMe):
            logger.debug('Stream #%i: sendme received', self.id)
            self._window.package_inc()
        else:
            raise Exception('Unknown stream cell received: %r', type(cell))

    def register(self, callback):
        self._received_callbacks.append(callback)

    def unregister(self, callback):
        self._received_callbacks.remove(callback)

    def _call_received(self):
        for callback in self._received_callbacks:
            callback(self, EVENT_READ)

    def send_relay(self, inner_cell):
        return self._circuit.send_relay(inner_cell, stream_id=self.id)

    def _append(self, data):
        with self._close_lock, self._data_lock:
            if self._state == StreamState.Closed:
                logger.warning('Stream #%i: closed (but received %r)', self.id, data)
                return

            if self.has_socket_loop:
                logger.debug('Stream #%i: append %i (to sock #%r)', self.id, len(data), self._loop.fileno)
                self._loop.append(data)
            else:
                logger.debug('Stream #%i: append %i (to buffer)', self.id, len(data))
                self._buffer.extend(data)
                self._has_data.set()

    def close(self):
        logger.info('Stream #%i: closing (state = %s)...', self.id, self._state.name)

        with self._close_lock:
            if self._state == StreamState.Closed:
                logger.warning('Stream #%i: closed already', self.id)
                return

            if self._state == StreamState.Connected:
                self.send_end()

            if self.has_socket_loop:
                self.close_socket()

            self._circuit.remove_stream(self)

            self._state = StreamState.Closed
            logger.debug('Stream #%i: closed', self.id)

    def _prepare_address(self, address):
        if isinstance(address[0], HiddenService):
            return address[0], (address[0].onion, address[1])
        elif address[0].endswith('.onion'):
            host_key = hostname_key(address[0])
            descriptor_cookie, auth_type = self._auth_data.get(host_key, HiddenService.HS_NO_AUTH)
            return HiddenService(address[0], descriptor_cookie, auth_type), address
        else:
            return None, address

    def connect(self, address):
        logger.info('Stream #%i: connecting to %r', self.id, address)
        assert self._state == StreamState.Closed
        self._state = StreamState.Connecting

        hidden_service, address = self._prepare_address(address)
        if hidden_service:
            self._circuit.extend_to_hidden(hidden_service)

        # Now we can connect to its address
        self._connect(address)

    def _wait_connected(self, address, timeout):
        start_time = time.time()
        while True:
            if time.time() - start_time > timeout:
                raise TimeoutError('Could not connect to %r' % (address,))

            if self._state == StreamState.Connected:
                return
            elif self._state == StreamState.Closed:
                raise ConnectionError('Could not connect to %r' % (address,))

            time.sleep(0.2)

    def connect_dir(self):
        logger.info('Stream #%i: connecting to hsdir', self.id)
        assert self._state == StreamState.Closed
        self._state = StreamState.Connecting

        inner_cell = CellRelayBeginDir()
        self.send_relay(inner_cell)
        self._wait_connected('hsdir', self._conn_timeout)

    def _connect(self, address):
        inner_cell = CellRelayBegin(address[0], address[1])
        self.send_relay(inner_cell)
        self._wait_connected(address, self._conn_timeout)

    def _connected(self, cell_connected):
        self._state = StreamState.Connected
        logger.info('Stream #%i: connected (remote ip %r)', self.id, cell_connected.address)

    def send(self, data):
        for chunk in chunks(data, RelayedTorCell.MAX_PAYLOD_SIZE):
            self._circuit.last_node.window.package_dec()
            self.send_relay(CellRelayData(chunk, self._circuit.id))

    def send_end(self) -> None:
        self.send_relay(CellRelayEnd(StreamReason.DONE, self._circuit.id))

    def send_sendme(self):
        self.send_relay(CellRelaySendMe(circuit_id=self._circuit.id))

    def _end(self, cell_end):
        logger.info('Stream #%i: remote disconnected (reason = %s)', self.id, cell_end.reason.name)
        with self._close_lock, self._data_lock:
            # For case when _end arrived later than we close
            if self._state == StreamState.Connected:
                self._state = StreamState.Disconnected

            if self.has_socket_loop:
                logger.debug('Close our sock...')
                self._loop.close_sock()
            else:
                self._has_data.set()

    def _create_socket_loop(self):
        our_sock, client_sock = socket.socketpair()
        logger.debug('Created sock pair: our_sock = %x, client_sock = %x', our_sock.fileno(), client_sock.fileno())

        # Flush data
        with self._data_lock:
            if len(self._buffer):
                logger.debug('Flush buffer')
                our_sock.send(self._buffer)
                self._buffer.clear()

            # Create proxy loop
            return client_sock, TorSocketLoop(our_sock, self.send)

    @contextmanager
    def as_socket(self):
        logger.debug('[as_socket] start')
        client_socket = self.create_socket()
        try:
            yield client_socket
        finally:
            logger.debug('[as_socket] finally')
            client_socket.close()
            self.close_socket()

    def create_socket(self, timeout=30):
        client_sock, self._loop = self._create_socket_loop()
        if timeout:
            client_sock.settimeout(timeout)
        self._loop.start()

        return client_sock

    def close_socket(self):
        self._loop.stop()
        self._loop.join()

    def recv(self, bufsize):
        if self.has_socket_loop:
            raise Exception('You must use socket')

        if self._state == StreamState.Closed:
            raise Exception("You can't recv closed stream")

        signaled = self._has_data.wait(self._recv_timeout)
        if not signaled:
            raise Exception('recv timeout')

        # If remote side already send 'end cell' but we still
        # has some data - we keep receiving
        if self._state == StreamState.Disconnected and not self._buffer:
            return b''

        with self._data_lock:
            if bufsize == -1:
                to_read = len(self._buffer)
            else:
                to_read = min(len(self._buffer), bufsize)
            result = self._buffer[:to_read]
            self._buffer = self._buffer[to_read:]
            logger.debug('Stream #%i: read %i (left %i)', self.id, to_read, len(self._buffer))

            # Clear 'has_data' flag only if we don't have more data and not disconnected
            if not self._buffer and self._state != StreamState.Disconnected:
                self._has_data.clear()

        return result


class StreamsList:
    LOCK = threading.Lock()
    GLOBAL_STREAM_ID = 0

    def __init__(self, circuit, auth_data):
        self._stream_map = {}
        self._circuit = circuit
        self._auth_data = auth_data

    @staticmethod
    def get_next_stream_id():
        with StreamsList.LOCK:
            StreamsList.GLOBAL_STREAM_ID += 1
            return StreamsList.GLOBAL_STREAM_ID

    def create_new(self):
        stream = TorStream(self.get_next_stream_id(), self._circuit, self._auth_data)
        self._stream_map[stream.id] = stream
        return stream

    def values(self):
        return self._stream_map.values()

    def remove(self, tor_stream):
        stream = self._stream_map.pop(tor_stream.id, None)
        if not stream:
            logger.debug('Stream #%i: not found in stream map', tor_stream.id)

    def get_by_id(self, stream_id):
        return self._stream_map.get(stream_id, None)
