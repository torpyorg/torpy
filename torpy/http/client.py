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

import gzip
import zlib
import logging
from io import BytesIO
from http.client import parse_headers

from torpy.utils import recv_all

logger = logging.getLogger(__name__)


class HttpStreamClient:
    def __init__(self, stream, host=None):
        self._stream = stream
        self._host = host

    def get(self, path, host=None, headers: dict = None):
        headers = headers or {}
        host = host or self._host
        if host:
            headers['Host'] = host
        headers_str = '\r\n'.join(f'{key}: {val}' for (key, val) in headers.items())
        http_query = f'GET {path} HTTP/1.0\r\n{headers_str}\r\n\r\n'
        self._stream.send(http_query.encode())

        raw_response = recv_all(self._stream)
        header, body = raw_response.split(b'\r\n\r\n', 1)

        f = BytesIO(header)
        request_line = f.readline().split(b' ')
        protocol, status = request_line[:2]
        status = int(status)

        headers = parse_headers(f)
        if headers['Content-Encoding'] == 'deflate':
            body = zlib.decompress(body)
        elif headers['Content-Encoding'] == 'gzip':
            body = gzip.decompress(body)

        if status != 200:
            logger.debug('raw_response = %s', raw_response)

        return status, body

    def close(self):
        self._stream.close()

    def __enter__(self):
        """Start using the http client."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Close the http client."""
        self.close()
