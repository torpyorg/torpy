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

import requests

from contextlib import contextmanager

from torpy.client import TorClient
from torpy.http.adapter import TorHttpAdapter


class TorRequests:
    def __init__(self, hops_count=3, headers=None, auth_data=None):
        self._hops_count = hops_count
        self._headers = dict(headers) if headers else {'User-Agent': 'Mozilla/5.0'}
        self._auth_data = dict(auth_data) if auth_data else auth_data

    def __enter__(self):
        self._tor = TorClient(auth_data=self._auth_data)
        self._guard = self._tor.get_guard()
        self._guard.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._guard.close()

    def send(self, method, url, data=None, **kwargs):
        with self.get_session() as s:
            r = requests.Request(method, url, data, **kwargs)
            return s.send(r.prepare())

    @contextmanager
    def get_session(self):
        adapter = TorHttpAdapter(self._guard, self._hops_count)
        with requests.Session() as s:
            s.headers.update(self._headers)
            s.mount('http://', adapter)
            s.mount('https://', adapter)
            yield s


@contextmanager
def tor_requests_session(hops_count=3, headers=None, auth_data=None):
    with TorRequests(hops_count, headers, auth_data) as tr:
        with tr.get_session() as s:
            yield s
