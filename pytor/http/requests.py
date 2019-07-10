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

from pytor.client import TorClient
from pytor.http.adapter import TorHttpAdapter


@contextmanager
def tor_requests_session(hops_count=3, headers=None, auth_data=None):
    # convert lists to dict
    headers = dict(headers) if headers else {'User-Agent': 'Mozilla/5.0'}
    auth_data = dict(auth_data) if auth_data else auth_data

    tor = TorClient(auth_data=auth_data)
    with tor.get_guard() as guard:
        adapter = TorHttpAdapter(guard, hops_count)
        with requests.Session() as s:
            s.headers.update(headers)
            s.mount('http://', adapter)
            s.mount('https://', adapter)
            yield s
