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

import os
import time
import threading
from contextlib import contextmanager

from selectors import DefaultSelector, EVENT_READ, EVENT_WRITE

from torpy.cells import *
from torpy.hiddenservice import HiddenService
from torpy.utils import chunks


logger = logging.getLogger(__name__)


class TorWindow:
    def __init__(self):
        self._lock = threading.Lock()
        self._start = 1000
        self._package = self._start
        self._deliver = self._start
        self._increment = 100

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

        self._cntrl_r, self._cntrl_w = socket.socketpair()

        self._selector = DefaultSelector()
        self._selector.register(self._our_sock, EVENT_READ, self._do_recv)
        self._selector.register(self._cntrl_r, EVENT_READ, self._do_stop)

    def _do_recv(self, sock):
        data = sock.recv(1024)
        self._send_func(data)

    def _do_stop(self, sock):
        self._do_loop = False

    def _cleanup(self):
        self._selector.unregister(self._cntrl_r)
        self._cntrl_w.close()
        self._cntrl_r.close()
        self._selector.unregister(self._our_sock)
        self._our_sock.shutdown(socket.SHUT_WR)
        self._our_sock.close()
        self._selector.close()

    def stop(self):
        self._cntrl_w.send(b'\1')

    def run(self):
        logger.debug("Starting...")
        while self._do_loop:
            events = self._selector.select()
            for key, _ in events:
                callback = key.data
                callback(key.fileobj)

        self._cleanup()
        logger.debug("Stopped...")

    def append(self, data):
        self._our_sock.send(data)


class StreamState:
    Connecting = 1
    Connected = 2
    Closing = 3
    Closed = 4


class TorStream:
    """
    This tor stream object implements socket-like interface
    """

    def __init__(self, id, circuit, auth_data):
        logger.info('Creating stream #%i attached to #%x circuit...', id, circuit.id)
        self._id = id
        self._circuit = circuit
        self._auth_data = auth_data

        self._buffer = bytearray()
        self._data_lock = threading.Lock()
        self._has_data = threading.Event()
        self._conn_timeout = 30
        self._recv_timeout = 60

        self._state = StreamState.Closed
        self._close_lock = threading.Lock()

        self._window = TorWindow()

        self._loop = None

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
        elif isinstance(cell, CellRelayData):
            self._append(cell.data)
            self._window.deliver_dec()
            if self._window.need_sendme():
                self._send_relay(CellRelaySendMe(circuit_id=cell.circuit_id))
        elif isinstance(cell, CellRelaySendMe):
            logger.debug('Stream #%i: sendme received', self.id)
            self._window.package_inc()
        else:
            raise Exception('Unknown stream cell received: %r', type(cell))

    def _send_relay(self, inner_cell):
        return self._circuit._send_relay(inner_cell, stream_id=self.id)

    def _append(self, data):
        with self._close_lock, self._data_lock:
            if self.has_socket_loop:
                logger.debug('Stream #%i: append %i (to sock #%x)', self.id, len(data), self._loop._our_sock.fileno())
                self._loop.append(data)
            else:
                logger.debug('Stream #%i: append %i (to buffer)', self.id, len(data))
                self._buffer.extend(data)
                self._has_data.set()

    def close(self):
        logger.info('Stream #%i: closing...', self.id)

        with self._close_lock:
            if self._state not in [StreamState.Connecting, StreamState.Connected]:
                logger.warning('Stream #%i: not connected yet', self.id)
                return
            elif self._state == StreamState.Closed:
                logger.warning('Stream #%i: closed already', self.id)
                return

            self._state = StreamState.Closing
            self._send_relay(CellRelayEnd(StreamReason.DONE, self._circuit.id))

            if self.has_socket_loop:
                self.close_socket()

            self._has_data.set()

            self._state = StreamState.Closed
            logger.debug('Stream #%i: closed', self.id)

    def _prepare_address(self, address):
        if isinstance(address[0], HiddenService):
            return address[0], (address[0].onion, address[1])
        elif address[0].endswith('.onion'):
            descriptor_cookie, auth_type = self._auth_data.get(address[0], (None, AuthType.No))
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
                raise TimeoutError("Could not connect to %r" % (address, ))

            if self._state == StreamState.Connected:
                return
            elif self._state == StreamState.Closed:
                raise Exception("Could not connect to %r" % (address, ))

            time.sleep(0.2)

    def connect_dir(self):
        logger.info('Stream #%i: connecting to hsdir', self.id)
        assert self._state == StreamState.Closed
        self._state = StreamState.Connecting

        inner_cell = CellRelayBeginDir()
        self._send_relay(inner_cell)
        self._wait_connected("hsdir", self._conn_timeout)

    def _connect(self, address):
        inner_cell = CellRelayBegin(address[0], address[1])
        self._send_relay(inner_cell)
        self._wait_connected(address, self._conn_timeout)

    def _connected(self, cell_connected):
        self._state = StreamState.Connected
        logger.debug('Stream #%i: connected (remote ip %r)', self.id, cell_connected.address)

    def _create_socket_loop(self):
        our_sock, client_sock = socket.socketpair()
        logger.debug("Created sock pair: our_sock = %x, client_sock = %x", our_sock.fileno(), client_sock.fileno())

        # Flush data
        with self._data_lock:
            if len(self._buffer):
                logger.debug("Flush buffer")
                our_sock.send(self._buffer)
                self._buffer.clear()

            # Create proxy loop
            return client_sock, TorSocketLoop(our_sock, self.send)

    @contextmanager
    def as_socket(self):
        logger.debug("[as_socket] start")
        client_socket = self.create_socket()
        try:
            yield client_socket
        finally:
            logger.debug("[as_socket] finally")
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

        while True:
            if len(self._buffer) != 0:
                break
            if self._state != StreamState.Connected:
                break
            signaled = self._has_data.wait(self._recv_timeout)
            if not signaled:
                raise Exception("recv timeout")

        with self._data_lock:
            if bufsize == -1:
                to_read = len(self._buffer)
            else:
                to_read = min(len(self._buffer), bufsize)
            result = self._buffer[:to_read]
            self._buffer = self._buffer[to_read:]
            logger.debug('Stream #%i: read %i (left %i)', self.id, to_read, len(self._buffer))
            if len(self._buffer) == 0:
                self._has_data.clear()

        return result

    def send(self, data):
        # logger.debug('write to tor_stream: %r', data)
        for chunk in chunks(data, RelayedTorCell.MAX_PAYLOD_SIZE):
            self._circuit.last_node.window.package_dec()
            self._send_relay(CellRelayData(chunk, self._circuit.id))


class StreamsManager:
    LOCK = threading.Lock()
    GLOBAL_STREAM_ID = 0

    def __init__(self, circuit, auth_data):
        self._stream_map = {}
        self._circuit = circuit
        self._auth_data = auth_data
        self._streams_lock = threading.Lock()
    
    @staticmethod
    def get_next_stream_id():
        with StreamsManager.LOCK:
            StreamsManager.GLOBAL_STREAM_ID += 1
            return StreamsManager.GLOBAL_STREAM_ID
        
    def create_new(self):
        stream = TorStream(self.get_next_stream_id(), self._circuit, self._auth_data)
        self._stream_map[stream.id] = stream
        return stream

    def streams(self):
        for stream in self._stream_map.values():
            yield stream

    def destroy(self, tor_stream):
        with self._streams_lock:
            connect = tor_stream.state in [StreamState.Connected, StreamState.Connecting]
            stream_id = tor_stream.id

            if connect:
                # Stream can be closed by remote already
                tor_stream.close()

            stream = self._stream_map.pop(stream_id, None)
            if not stream and connect:
                logger.error('Stream #%i: not found in stream map', stream_id)

    def get_by_id(self, stream_id):
        return self._stream_map.get(stream_id, None)
