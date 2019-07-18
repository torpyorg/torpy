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

import traceback
import logging
import threading

from requests.adapters import HTTPAdapter, DEFAULT_POOLBLOCK
from requests.packages.urllib3.poolmanager import PoolManager, HTTPConnectionPool, HTTPSConnectionPool
from requests.packages.urllib3.connection import HTTPConnection, VerifiedHTTPSConnection
from requests.packages.urllib3.exceptions import ConnectTimeoutError, NewConnectionError

#from urllib3.poolmanager import HTTPSConnectionPool
#from urllib3.connection import  HTTPConnection, HTTPSConnection
logger = logging.getLogger(__name__)


class TorInfo:
    def __init__(self, guard, hops_count):
        self._guard = guard
        self._hops_count = hops_count
        self._circuits = {}
        self._lock = threading.Lock()

    def get_circuit(self, host):
        host_key = '.'.join(host.split('.')[-2:])
        logger.debug("[TorInfo] Waiting lock...")
        with self._lock:
            logger.debug("[TorInfo] Got lock...")
            circuit = self._circuits.get(host_key)
            if not circuit:
                logger.debug('[TorInfo] Create new circuit for %s (key %s)', host, host_key)
                circuit = self._guard.create_circuit_(self._hops_count)
                self._circuits[host_key] = circuit
            else:
                logger.debug("[TorInfo] Use existing...")
            return circuit


class TorHttpAdapter(HTTPAdapter):
    def __init__(self, guard, hops_count):
        self._tor_info = TorInfo(guard, hops_count)
        super().__init__()

    def init_poolmanager(self, connections, maxsize, block=DEFAULT_POOLBLOCK, **pool_kwargs):
        # save these values for pickling
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block

        self.poolmanager = MyPoolManager(self._tor_info, num_pools=connections, maxsize=maxsize,
                                         block=block, strict=True, **pool_kwargs)


class MyPoolManager(PoolManager):
    def __init__(self, tor_info, *args, **kwargs):
        self._tor_info = tor_info
        super().__init__(*args, **kwargs)

    def _new_pool(self, scheme, host, port):
        assert scheme in ['http', 'https']
        pool_kwargs = self.connection_pool_kw.copy()
        if scheme == 'http':
            return MyHTTPConnectionPool(self._tor_info, host, port, **pool_kwargs)
        else:
            return MyHTTPSConnectionPool(self._tor_info, host, port, **pool_kwargs)


class MyHTTPConnectionPool(HTTPConnectionPool):
    def __init__(self, tor_info, *args, **kwargs):
        self._tor_info = tor_info
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        self.num_connections += 1
        logger.debug("[MyHTTPConnectionPool] new_conn %i", self.num_connections)
        circuit = self._tor_info.get_circuit(self.host)
        return MyHTTPConnection(circuit, host=self.host, port=self.port,
                                timeout=self.timeout.connect_timeout,
                                strict=self.strict, **self.conn_kw)


class MyHTTPSConnectionPool(HTTPSConnectionPool):
    def __init__(self, tor_info, *args, **kwargs):
        self._tor_info = tor_info
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        self.num_connections += 1
        logger.debug("[MyHTTPSConnectionPool] new_conn %i", self.num_connections)
        circuit = self._tor_info.get_circuit(self.host)
        conn = MyHTTPSConnection(circuit, host=self.host, port=self.port,
                                 timeout=self.timeout.connect_timeout,
                                 strict=self.strict, **self.conn_kw)
        logger.debug("[MyHTTPSConnectionPool] preparing...")
        return self._prepare_conn(conn)
        # TODO: override close to close all circuits?


class MyHTTPConnection(HTTPConnection):
    def __init__(self, circuit, *args, **kwargs):
        self._circuit = circuit
        self._tor_stream = None
        super().__init__(*args, **kwargs)

    def connect(self):
        logger.debug('[MyHTTPConnection] connect %s:%i', self.host, self.port)
        try:
            self._tor_stream = self._circuit.create_stream_((self.host, self.port))
            logger.debug('[MyHTTPConnection] tor_stream create_socket')
            self.sock = self._tor_stream.create_socket()
            if self._tunnel_host:
                self._tunnel()
        except TimeoutError as e:
            logger.error("TimeoutError")
            raise ConnectTimeoutError(self, "Connection to %s timed out. (connect timeout=%s)" % (self.host, self.timeout))
        except Exception as e:
            logger.error("NewConnectionError")
            raise NewConnectionError(self, "Failed to establish a new connection: %s" % e)

    def close(self):
        # WARN: self.sock will be closed inside base class
        logger.debug('[MyHTTPConnection] closing')
        super().close()
        logger.debug('[MyHTTPConnection] circuit destroy_stream')
        if self._tor_stream:
            self._circuit.destroy_stream(self._tor_stream)
        logger.debug('[MyHTTPConnection] closed')


class MyHTTPSConnection(VerifiedHTTPSConnection):

    def __init__(self, circuit, *args, **kwargs):
        self._circuit = circuit
        self._tor_stream = None
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        logger.debug('[MyHTTPSConnection] new conn %s:%i', self.host, self.port)
        try:
            self._tor_stream = self._circuit.create_stream_((self.host, self.port))
            logger.debug('[MyHTTPSConnection] tor_stream create_socket')
            return self._tor_stream.create_socket()
        except TimeoutError as e:
            logger.error("TimeoutError")
            raise ConnectTimeoutError(self, "Connection to %s timed out. (connect timeout=%s)" % (self.host, self.timeout))
        except Exception as e:
            logger.error("NewConnectionError")
            raise NewConnectionError(self, "Failed to establish a new connection: %s" % e)

    def close(self):
        logger.debug('[MyHTTPSConnection] closing')
        super().close()
        logger.debug('[MyHTTPSConnection] circuit destroy_stream')
        if self._tor_stream:
            self._circuit.destroy_stream(self._tor_stream)
        logger.debug('[MyHTTPSConnection] closed')
