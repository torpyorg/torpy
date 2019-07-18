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

from torpy.utils import recv_all


class HttpClient:
    def __init__(self, sock):
        self._sock = sock

    def get(self, host, path):
        http_query = 'GET {} HTTP/1.0\r\nHost: {}\r\n\r\n'.format(path, host)
        self._sock.send(http_query.encode())
        return recv_all(self._sock)
