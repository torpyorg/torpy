import threading
import logging

from torpy.utils import hostname_key

logger = logging.getLogger(__name__)


class SocketProxy:
    def __init__(self, sock, tor_stream):
        self._sock = sock
        self._tor_stream = tor_stream

    def __getattr__(self, attr):
        """Proxying methods to real socket."""
        if attr in self.__dict__:
            return getattr(self, attr)
        return getattr(self._sock, attr)

    @classmethod
    def rewrap(cls, prev_proxy, new_sock):
        return cls(new_sock, prev_proxy.tor_stream)

    @property
    def wrapped_sock(self):
        return self._sock

    @property
    def tor_stream(self):
        return self._tor_stream

    def close(self):
        logger.debug('[SocketProxy] close')
        self.close_tor_stream()
        self._sock.close()

    def close_tor_stream(self):
        self._tor_stream.close()


class TorInfo:
    def __init__(self, guard, hops_count):
        self._guard = guard
        self._hops_count = hops_count
        self._circuits = {}
        self._lock = threading.Lock()

    def get_circuit(self, hostname):
        host_key = hostname_key(hostname)
        logger.debug('[TorInfo] Waiting lock...')
        with self._lock:
            logger.debug('[TorInfo] Got lock...')
            circuit = self._circuits.get(host_key)
            if not circuit:
                logger.debug('[TorInfo] Create new circuit for %s (key %s)', hostname, host_key)
                circuit = self._guard.create_circuit(self._hops_count)
                self._circuits[host_key] = circuit
            else:
                logger.debug('[TorInfo] Use existing...')
            return circuit

    def connect(self, address, timeout=30, source_address=None):
        circuit = self.get_circuit(address[0])
        tor_stream = circuit.create_stream(address)
        logger.debug('[TorHTTPConnection] tor_stream create_socket')
        return SocketProxy(tor_stream.create_socket(), tor_stream)
