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
import socket
from typing import ContextManager
from contextlib import contextmanager
from http.client import HTTPConnection, HTTPSConnection, HTTPResponse
from urllib.error import URLError
from urllib.request import (
    Request,
    OpenerDirector,
    ProxyHandler,
    UnknownHandler,
    HTTPRedirectHandler,
    HTTPDefaultErrorHandler,
    HTTPErrorProcessor,
    HTTPHandler,
    HTTPSHandler,
)

from torpy.http.base import TorInfo, SocketProxy
from torpy import TorClient

logger = logging.getLogger(__name__)


class TorHTTPResponse(HTTPResponse):
    def __init__(self, sock, debuglevel=0, method=None, url=None):
        logger.debug('[TorHTTPResponse] init')
        super().__init__(sock, debuglevel=debuglevel, method=method, url=url)
        self._sock = sock

    def close(self):
        self._sock.close_tor_stream()
        super().close()


class TorHTTPConnection(HTTPConnection):
    response_class = TorHTTPResponse
    # debuglevel = 1

    def __init__(self, *args, **kwargs):
        self._tor_info = kwargs.pop('tor_info')
        super().__init__(*args, **kwargs)

    def connect(self):
        """Connect to the host and port specified in __init__."""
        self.sock = self._tor_info.connect((self.host, self.port), self.timeout, self.source_address)

        if self._tunnel_host:
            self._tunnel()

    def close(self):
        logger.debug('[TorHTTPConnection] close')
        super().close()


class TorHTTPSConnection(TorHTTPConnection, HTTPSConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def connect(self):
        TorHTTPConnection.connect(self)

        if self._tunnel_host:
            server_hostname = self._tunnel_host
        else:
            server_hostname = self.host

        ssl_sock = self._context.wrap_socket(self.sock.wrapped_sock, server_hostname=server_hostname)
        self.sock = SocketProxy.rewrap(self.sock, ssl_sock)


class TorHTTPHandler(HTTPHandler):
    def __init__(self, guard, hops_count, debuglevel=0):
        super().__init__(debuglevel=debuglevel)
        self._tor_info = TorInfo(guard, hops_count)

    def http_open(self, req):
        return self.do_open(TorHTTPConnection, req, tor_info=self._tor_info)


class TorHTTPSHandler(HTTPSHandler):
    def __init__(self, guard, hops_count, debuglevel=0, context=None, check_hostname=None):
        super().__init__(debuglevel=debuglevel, context=context, check_hostname=check_hostname)
        self._tor_info = TorInfo(guard, hops_count)

    def https_open(self, req):
        return self.do_open(TorHTTPSConnection, req,
                            context=self._context, check_hostname=self._check_hostname, tor_info=self._tor_info)


class RetryOpenerDirector(OpenerDirector):
    def open(self, fullurl, retries=1, *args, **kwargs):
        assert retries >= 1
        last_err = None
        for _ in range(retries):
            try:
                return super().open(fullurl, *args, **kwargs)
            except URLError as err:
                last_err = err
                if not isinstance(err.reason, socket.timeout):
                    raise
        else:
            raise last_err


def build_tor_opener(guard, hops_count=3, debuglevel=0):
    opener = RetryOpenerDirector()
    default_classes = [ProxyHandler, UnknownHandler,
                       HTTPDefaultErrorHandler, HTTPRedirectHandler,
                       HTTPErrorProcessor]
    for cls in default_classes:
        opener.add_handler(cls())
    opener.add_handler(TorHTTPHandler(guard, hops_count, debuglevel=debuglevel))
    opener.add_handler(TorHTTPSHandler(guard, hops_count, debuglevel=debuglevel))
    opener.addheaders = []
    return opener


@contextmanager
def tor_opener(hops_count=3, debuglevel=0, auth_data=None) -> ContextManager[RetryOpenerDirector]:
    with TorClient(auth_data=auth_data) as tor:
        with tor.get_guard() as guard:
            yield build_tor_opener(guard, hops_count=hops_count, debuglevel=debuglevel)


def do_request(url, method='GET', data=None, headers=None, hops=3, auth_data=None, verbose=0, retries=3):
    with tor_opener(hops_count=hops, auth_data=auth_data, debuglevel=verbose) as opener:
        request = Request(url, data, method=method, headers=dict(headers or []))

        logger.warning('Sending: %s %s', request.get_method(), request.full_url)
        with opener.open(request, retries=retries) as response:
            logger.warning('Response status: %r', response.status)
            logger.debug('Reading...')
            return response.read().decode('utf-8')
