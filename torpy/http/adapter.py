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

from requests.adapters import DEFAULT_POOLBLOCK, HTTPAdapter
try:
    from requests.packages.urllib3.connection import HTTPConnection, VerifiedHTTPSConnection
    from requests.packages.urllib3.exceptions import NewConnectionError, ConnectTimeoutError
    from requests.packages.urllib3.poolmanager import PoolManager, HTTPConnectionPool, HTTPSConnectionPool
except ImportError:
    # requests >=2.16
    from urllib3.connection import HTTPConnection, VerifiedHTTPSConnection
    from urllib3.exceptions import NewConnectionError, ConnectTimeoutError
    from urllib3.poolmanager import PoolManager, HTTPConnectionPool, HTTPSConnectionPool

from torpy.http.base import TorInfo

logger = logging.getLogger(__name__)


class TorHttpAdapter(HTTPAdapter):
    def __init__(self, guard, hops_count, retries=0):
        self._tor_info = TorInfo(guard, hops_count)
        super().__init__(max_retries=retries)

    def init_poolmanager(self, connections, maxsize, block=DEFAULT_POOLBLOCK, **pool_kwargs):
        # save these values for pickling
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block

        self.poolmanager = MyPoolManager(
            self._tor_info, num_pools=connections, maxsize=maxsize, block=block, strict=True, **pool_kwargs
        )


def wrap_normalizer(base_normalizer):
    def wrapped(request_context, *args, **kwargs):
        context = request_context.copy()
        context.pop('tor_info')
        return base_normalizer(context, *args, **kwargs)
    return wrapped


class MyPoolManager(PoolManager):
    def __init__(self, tor_info, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pool_classes_by_scheme = {
            'http': MyHTTPConnectionPool,
            'https': MyHTTPSConnectionPool,
        }
        # for requests >= 2.11
        if hasattr(self, 'key_fn_by_scheme'):
            self.key_fn_by_scheme = {
                'http': wrap_normalizer(self.key_fn_by_scheme['http']),
                'https': wrap_normalizer(self.key_fn_by_scheme['https']),
            }
        self.connection_pool_kw['tor_info'] = tor_info


class MyHTTPConnectionPool(HTTPConnectionPool):
    def __init__(self, *args, **kwargs):
        self._tor_info = kwargs.pop('tor_info')
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        self.num_connections += 1
        logger.debug('[MyHTTPConnectionPool] new_conn %i', self.num_connections)
        circuit = self._tor_info.get_circuit(self.host)
        return MyHTTPConnection(
            circuit,
            host=self.host,
            port=self.port,
            timeout=self.timeout.connect_timeout,
            strict=self.strict,
            **self.conn_kw,
        )


class MyHTTPSConnectionPool(HTTPSConnectionPool):
    def __init__(self, *args, **kwargs):
        self._tor_info = kwargs.pop('tor_info')
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        self.num_connections += 1
        logger.debug('[MyHTTPSConnectionPool] new_conn %i', self.num_connections)
        circuit = self._tor_info.get_circuit(self.host)
        conn = MyHTTPSConnection(
            circuit,
            host=self.host,
            port=self.port,
            timeout=self.timeout.connect_timeout,
            strict=self.strict,
            **self.conn_kw,
        )
        logger.debug('[MyHTTPSConnectionPool] preparing...')
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
            self._tor_stream = self._circuit.create_stream((self.host, self.port))
            logger.debug('[MyHTTPConnection] tor_stream create_socket')
            self.sock = self._tor_stream.create_socket()
            if self._tunnel_host:
                self._tunnel()
        except TimeoutError:
            logger.error('TimeoutError')
            raise ConnectTimeoutError(
                self, 'Connection to %s timed out. (connect timeout=%s)' % (self.host, self.timeout)
            )
        except Exception as e:
            logger.error('NewConnectionError')
            raise NewConnectionError(self, 'Failed to establish a new connection: %s' % e)

    def close(self):
        # WARN: self.sock will be closed inside base class
        logger.debug('[MyHTTPConnection] closing')
        super().close()
        logger.debug('[MyHTTPConnection] circuit destroy_stream')
        if self._tor_stream:
            self._tor_stream.close()
        logger.debug('[MyHTTPConnection] closed')


class MyHTTPSConnection(VerifiedHTTPSConnection):
    def __init__(self, circuit, *args, **kwargs):
        self._circuit = circuit
        self._tor_stream = None
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        logger.debug('[MyHTTPSConnection] new conn %s:%i', self.host, self.port)
        try:
            self._tor_stream = self._circuit.create_stream((self.host, self.port))
            logger.debug('[MyHTTPSConnection] tor_stream create_socket')
            return self._tor_stream.create_socket()
        except TimeoutError:
            logger.error('TimeoutError')
            raise ConnectTimeoutError(
                self, 'Connection to %s timed out. (connect timeout=%s)' % (self.host, self.timeout)
            )
        except Exception as e:
            logger.error('NewConnectionError')
            raise NewConnectionError(self, 'Failed to establish a new connection: %s' % e)

    def close(self):
        logger.debug('[MyHTTPSConnection] closing %s', self.host)
        super().close()
        logger.debug('[MyHTTPSConnection] circuit destroy_stream')
        if self._tor_stream:
            self._tor_stream.close()
        logger.debug('[MyHTTPSConnection] closed')
