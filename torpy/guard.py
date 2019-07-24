import logging
import functools
from contextlib import contextmanager

from torpy.cell_socket import TorCellSocket
from torpy.cells import CellDestroy, CellCreated2, CellRelay, CellRelayTruncated
from torpy.circuit import CellHandlerManager, TorReceiver, CircuitExtendError, CellTimeoutError, CircuitsManager
from torpy.utils import retry, log_retry

logger = logging.getLogger(__name__)


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


class TorSender:
    def __init__(self, tor_socket):
        self._tor_socket = tor_socket

    def send(self, cell):
        self._tor_socket.send_cell(cell)


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
        """Return Guard object."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Disconnect from Guard node."""
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

    @retry(3, (CircuitExtendError, CellTimeoutError,),
           log_func=functools.partial(log_retry, msg='Retry circuit creation'))
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
