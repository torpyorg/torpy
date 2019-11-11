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

import os
import logging

from torpy.utils import user_data_dir
from torpy.documents import TorDocument

logger = logging.getLogger(__name__)


class TorCacheStorage:
    def load(self, key):
        raise NotImplementedError()

    def load_document(self, doc_cls, **kwargs):
        assert issubclass(doc_cls, TorDocument)
        ident, content = self.load(doc_cls.DOCUMENT_NAME)
        if content:
            logger.info('Loading cached %s from %s: %s', doc_cls.__name__, self.__class__.__name__, ident)
            return doc_cls(content, **kwargs)
        else:
            return None

    def save(self, key, content):
        raise NotImplementedError()

    def save_document(self, doc):
        assert isinstance(doc, TorDocument)
        self.save(doc.DOCUMENT_NAME, doc.raw_string)


class TorCacheDirStorage(TorCacheStorage):
    def __init__(self, base_dir=None):
        self._base_dir = base_dir or user_data_dir('torpy')
        if not os.path.isdir(self._base_dir):
            os.makedirs(self._base_dir)

    def load(self, key):
        file_path = os.path.join(self._base_dir, key)
        if os.path.isfile(file_path):
            with open(os.path.join(self._base_dir, key), 'r') as f:
                return file_path, f.read()
        else:
            return file_path, None

    def save(self, key, content):
        with open(os.path.join(self._base_dir, key), 'w') as f:
            f.write(content)


class NoCacheStorage(TorCacheStorage):
    def load(self, key):
        return None, None

    def save(self, key, content):
        pass
