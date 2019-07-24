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
import functools
from contextlib import contextmanager

from torpy.guard import TorGuard
from torpy.utils import retry, log_retry
from torpy.consesus import TorConsensus
from torpy.cache_storage import TorCacheDirStorage

logger = logging.getLogger(__name__)


class TorClient:
    def __init__(self, consensus=None, auth_data=None):
        self._consensus = consensus or TorConsensus()
        self._auth_data = auth_data or {}

    @classmethod
    def create(cls, authorities=None, cache_class=None, cache_kwargs=None, auth_data=None):
        cache_class = cache_class or TorCacheDirStorage
        cache_kwargs = cache_kwargs or {}
        consensus = TorConsensus(authorities=authorities, cache_storage=cache_class(**cache_kwargs))
        return cls(consensus, auth_data)

    @retry(3, Exception, log_func=functools.partial(log_retry, msg='Retry with another guard...'))
    def get_guard(self, by_flags=None):
        # TODO: add another stuff to filter guards
        guard_router = self._consensus.get_random_guard_node(by_flags)
        guard = TorGuard(guard_router, self._consensus, self._auth_data)
        guard.connect()
        return guard

    @contextmanager
    def create_circuit(self, hops_count=3, guard_by_flags=None):
        with self.get_guard(guard_by_flags) as guard:
            with guard.create_circuit(hops_count) as circuit:
                yield circuit
