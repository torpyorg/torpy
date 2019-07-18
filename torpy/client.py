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
import functools
import threading

from contextlib import contextmanager

from torpy.consesus import TorConsensus
from torpy.circuit import TorCircuit, TorReceiver, CellHandlerManager, CircuitExtendError, CellTimeoutError
from torpy.cells import *
from torpy.utils import retry, log_retry
from torpy.cell_socket import TorCellSocket

logger = logging.getLogger(__name__)


class CircuitsManager:
    LOCK = threading.Lock()
    GLOBAL_CIRCUIT_ID = 0

    def __init__(self, router, sender, consensus, auth_data):
        self._router = router
        self._sender = sender
        self._consensus = consensus
        self._auth_data = auth_data

        self._circuits_map = {}

    def circuits(self):
        for circuit in self._circuits_map.values():
            yield circuit

    #def destroy_all(self):

    #    for circuit in self._circuits_map.values():
    #        circuit.destroy()
    #    self._circuits_map.clear()

    @staticmethod
    def _get_next_circuit_id(msb=True):
        # self._circuit_id = 1 # random.randint(2 ** 31, (2 ** 32) - 1)  # C int value range (4 bytes)
        # self._circuit_id |= 0x80000000
        with CircuitsManager.LOCK:
            CircuitsManager.GLOBAL_CIRCUIT_ID += 1
            circuit_id = CircuitsManager.GLOBAL_CIRCUIT_ID
        if msb:
            circuit_id |= 0x80000000
        return circuit_id

    def create_new(self):
        circuit_id = self._get_next_circuit_id()
        circuit = TorCircuit(circuit_id, self._router, self._sender, self._consensus, self._auth_data)
        self._circuits_map[circuit.id] = circuit
        return circuit

    def get_by_id(self, circuit_id):
        return self._circuits_map.get(circuit_id, None)

    def remove(self, circuit_id):
        return self._circuits_map.pop(circuit_id, None)


class TorSender:
    def __init__(self, tor_socket):
        self._tor_socket = tor_socket

    def send(self, cell):
        self._tor_socket.send_cell(cell)


class GuardState:
    Disconnecting = 1
    Disconnected = 2
    Connecting = 3
    Connected = 4


def cell_to_circuit(func):
    def wrapped(_self, cell, *args, **kwargs):
        circuit = _self._circuits_manager.get_by_id(cell.circuit_id)
        if not circuit:
            if _self._state != GuardState.Connected:
                logger.debug("Ignore not found circuits on %r state", _self._state)
                return
            raise Exception('Circuit #{:x} not found'.format(cell.circuit_id))
        args_new = [_self, cell, circuit] + list(args)
        return func(*args_new, **kwargs)
    return wrapped


class TorGuard:
    def __init__(self, router, consensus, auth_data):
        self._router = router
        self._consensus = consensus
        self._auth_data = auth_data

        self.__tor_socket = None
        self._circuits_manager = None
        self._handler_mgr = None
        self._sender = None
        self._receiver = None
        self._state = GuardState.Disconnected

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def connect(self):
        logger.info('Connecting to guard node %s...', self._router)
        self._state = GuardState.Connecting
        self.__tor_socket = TorCellSocket(self._router)
        self.__tor_socket.connect()

        self._sender = TorSender(self.__tor_socket)
        self._circuits_manager = CircuitsManager(self._router, self._sender, self._consensus, self._auth_data)

        self._handler_mgr = CellHandlerManager()
        self._handler_mgr.subscribe_for(CellDestroy, self._on_destroy)
        self._handler_mgr.subscribe_for(CellCreated2, self._on_cell)
        self._handler_mgr.subscribe_for(CellRelay, self._on_relay)

        self._receiver = TorReceiver(self.__tor_socket, self._handler_mgr)
        self._receiver.start()

        self._state = GuardState.Connected

    def close(self):
        logger.info('Closing guard connections...')
        self._state = GuardState.Disconnecting
        self._destroy_all_circuits()
        self._receiver.stop()
        self.__tor_socket.close()
        self._state = GuardState.Disconnected

    def _destroy_all_circuits(self):
        logger.debug('Destroying all circuits...')
        for circuit in list(self._circuits_manager.circuits()):
            self.destroy_circuit(circuit)

    def _get_circuit(self, circuit_id):
        circuit = self._circuits_manager.get_by_id(circuit_id)
        if not circuit:
            if self._state != GuardState.Connected:
                return
            raise Exception('Circuit #{:x} not found'.format(circuit_id))
        return circuit

    @cell_to_circuit
    def _on_destroy(self, cell, circuit):
        logger.info('On destroy: circuit #%x', cell.circuit_id)
        send_destroy = isinstance(cell, CellRelayTruncated)
        self.destroy_circuit(circuit, send_destroy=send_destroy)

    @cell_to_circuit
    def _on_cell(self, cell, circuit):
        circuit.handle_cell(cell)

    @cell_to_circuit
    def _on_relay(self, cell: CellRelay, circuit):
        circuit.handle_relay(cell)

    @retry(3, (CircuitExtendError, CellTimeoutError,), log_func=functools.partial(log_retry, msg='Retry circuit creation'))
    def create_circuit_(self, hops_count):
        if self._state != GuardState.Connected:
            raise Exception('You must connect to guard node first')

        circuit = self._circuits_manager.create_new()
        try:
            circuit.create(self)
            circuit.build_hops(hops_count)
        except CellTimeoutError:
            self.destroy_circuit(circuit)
            raise

        return circuit

    @contextmanager
    def create_circuit(self, hops_count):
        circuit = self.create_circuit_(hops_count)
        try:
            yield circuit
        finally:
            self.destroy_circuit(circuit)

    def destroy_circuit(self, circuit, send_destroy=True):
        logger.info('Destroy circuit #%x', circuit.id)
        circuit.destroy(send_destroy=send_destroy)
        self._circuits_manager.remove(circuit.id)


class TorClient:
    def __init__(self, consensus=None, auth_data=None):
        self._consensus = consensus or TorConsensus()
        self._auth_data = auth_data or {}

    def get_guard(self, by_flags=None):
        # TODO: add another stuff to filter guards
        guard_router = self._consensus.get_random_guard_node(by_flags)
        guard = TorGuard(guard_router, self._consensus, self._auth_data)
        return guard

    @retry(3, Exception, log_func=functools.partial(log_retry, msg='Retry with another guard...'))
    def _get_guard_connect(self, by_flags):
        guard = self.get_guard(by_flags=by_flags)
        guard.connect()
        return guard

    @contextmanager
    def create_circuit(self, hops_count=3, guard_by_flags=None):
        guard = self._get_guard_connect(guard_by_flags)
        try:
            with guard.create_circuit(hops_count) as circuit:
                yield circuit
        except Exception as e:
            logger.error(e)
            raise
        finally:
            guard.close()
