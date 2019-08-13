import os
import logging

from torpy.documents import TorDocument
from torpy.utils import user_data_dir

logger = logging.getLogger(__name__)


class TorCacheStorage:
    def load(self, key):
        raise NotImplementedError()

    def load_document(self, doc_cls, **kwargs):
        assert issubclass(doc_cls, TorDocument)
        ident, content = self.load(doc_cls.DOCUMENT_NAME)
        if content:
            logger.info("Loading cached %s from %s: %s", doc_cls.__name__, self.__class__.__name__, ident)
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
            os.mkdir(self._base_dir)

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
