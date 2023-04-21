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

from requests import Request, Session

try:
    from urllib3.util import SKIP_HEADER
except Exception:
    SKIP_HEADER = None

from torpy.client import TorClient
from torpy.http.adapter import TorHttpAdapter

logger = logging.getLogger(__name__)

class TorRequests(Session):
    def __init__(self, hops_count=3, headers=None, auth_data=None, retries=0):
        super().__init__()
        self._hops_count = hops_count
        self._headers = dict(headers) if headers else {}
        self._auth_data = dict(auth_data) if auth_data else auth_data
        self._tor = TorClient(auth_data=self._auth_data)
        self._guard = self._tor.get_guard()
        self.headers.update(self._headers)
        adapter = TorHttpAdapter(self._guard, self._hops_count, retries=retries)
        self.mount('http://', adapter)
        self.mount('https://', adapter)

    def close(self):
        super().close()
        self._guard.close()
        self._tor.close()

def tor_requests_session(hops_count=3, headers=None, auth_data=None, retries=0):
    return TorRequests(hops_count, headers, auth_data, retries)

def do_request(url, method='GET', data=None, headers=None, hops=3, auth_data=None, verbose=0, retries=0):
    with tor_requests_session(hops, auth_data, retries=retries) as s:
        headers = dict(headers or [])
        if SKIP_HEADER and \
                'user-agent' not in (k.lower() for k in headers.keys()):
            headers['User-Agent'] = SKIP_HEADER
        request = Request(method, url, data=data, headers=headers)
        logger.warning('Sending: %s %s', request.method, request.url)
        response = s.send(request.prepare())
        logger.warning('Response status: %r', response.status_code)
        return response.text
