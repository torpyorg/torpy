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

import io

from torpy.crypto_common import hash_stream, hash_update, hash_finalize
from torpy.documents.items import ItemObject, ItemMask


class TorDocumentObject:
    START_ITEM = None
    ITEMS = None
    CLASS = None

    def __init__(self, check_start=False):
        if self.START_ITEM is None or self.ITEMS is None:
            raise Exception('You must fill items for this object')
        self._check_start = check_start
        self._fields = {}

    def __getattr__(self, item):
        """Hooks fields search."""
        if item in self._fields:
            return self._fields[item]

    @classmethod
    def from_item_result(cls, item, result):
        o = cls()
        o._update(item, result)
        return o

    def _update(self, item, result):
        if item.as_list:
            key = item.out_name
            if key not in self._fields:
                self._fields[key] = []
            self._fields[key].append(result)
        else:
            if type(result) is dict:
                self._fields.update(result)
            else:
                self._fields[item.out_name] = result


class TorDocumentReader:
    def __init__(self, document_string, digests_names=None, digest_start=None, digest_end=None):
        self._f = io.StringIO(document_string)
        self._digests_names = digests_names or []
        self._digests = [hash_stream(digest) for digest in self._digests_names]
        self._digest_start = digest_start
        self._digest_end = digest_end
        self._digesting = False

    def _update_digests(self, data):
        for h in self._digests:
            hash_update(h, data.encode('utf-8'))

    def get_digests(self):
        return {self._digests_names[i]: hash_finalize(h) for i, h in enumerate(self._digests)}

    def lines_gen(self):
        for line in self._f:
            if self._digests_names:
                if not self._digesting:
                    i = line.find(self._digest_start)
                    if i >= 0:
                        self._update_digests(line[i:])
                        self._digesting = True
                else:
                    i = line.find(self._digest_end)
                    if i >= 0:
                        self._update_digests(line[:i + len(self._digest_end)])
                        self._digesting = False
                    else:
                        self._update_digests(line)

            yield line.rstrip('\n')


class TorDocument(TorDocumentObject):
    DOCUMENT_NAME = None

    def __init__(self, raw_string, digests_names=None, digest_start=None, digest_end=None):
        if self.DOCUMENT_NAME is None:
            raise Exception('You must fill document name field')
        super().__init__(check_start=True)
        self._raw_string = raw_string
        self._digests = {}
        self._items, self._items_obj, self._items_mask = self._collect_items()
        self._read(digests_names, digest_start, digest_end)

    @classmethod
    def check_start(cls, raw_string):
        return raw_string.startswith(cls.START_ITEM.keyword + ' ')

    def get_digest(self, hash_name):
        return self._digests.get(hash_name, None)

    def _collect_items(self):
        items = {}
        items_obj = {}
        items_mask = []

        if self.START_ITEM:
            items[self.START_ITEM.keyword] = self.START_ITEM, True

        for item in self.ITEMS:
            if type(item) is ItemObject:
                items_obj[item.object_cls.START_ITEM.keyword] = item.object_cls.START_ITEM, item, True
                for sub_item in item.object_cls.ITEMS:
                    items_obj[sub_item.keyword] = sub_item, item, False
            elif isinstance(item, ItemMask):
                items_mask.append(item)
            else:
                items[item.keyword] = item, False

        return items, items_obj, items_mask

    def check_items(self, line, lines):
        t = line.split(' ', 1)
        if len(t) < 2:
            kw, rest = t[0], ''
        else:
            kw, rest = t

        if self._items:
            t = self._items.get(kw, None)
            if t:
                item, st = t
                if self._check_start:
                    if not st:
                        raise Exception(
                            f'"{self.DOCUMENT_NAME}" document must start with "{self.START_ITEM.keyword} " item'
                        )
                    else:
                        self._check_start = False

                # Parse line
                result = item.parse_func(rest, lines, *item.parse_args)
                self._update(item, result)
                return

        if self._items_obj:
            t = self._items_obj.get(kw, None)
            if t:
                item, oitem, st = t
                if st:
                    result = item.parse_func(rest, lines, *item.parse_args)
                    if result:
                        # Start new object
                        obj = oitem.object_cls.from_item_result(item, result)
                        self._update(oitem, obj)
                        return
                else:
                    obj_lst = getattr(self, oitem.out_name, None)
                    if not obj_lst:
                        # Skip this item because it's not started yet
                        return
                    result = item.parse_func(rest, lines, *item.parse_args)
                    # Grab last one
                    obj = obj_lst[-1]
                    obj._update(item, result)
                    return

        for item in self._items_mask:
            m = item.check_item(kw)
            if m:
                result = item.parse_func(line, m, lines)
                self._update(item, result)
                return
        return

    def _fix_objects(self):
        for t in self._items_obj.values():
            if t:
                item, oitem, st = t
                if not oitem.object_cls.CLASS:
                    continue
                obj_lst = getattr(self, oitem.out_name, None)
                for i, obj in enumerate(obj_lst):
                    if not hasattr(obj, 'CLASS'):
                        break
                    obj_lst[i] = obj.CLASS(**obj._fields)

    def _read(self, digests_names, digest_start, digest_end):
        reader = TorDocumentReader(self._raw_string, digests_names, digest_start, digest_end)
        lines = reader.lines_gen()
        for line in lines:
            self.check_items(line, lines)
        self._fix_objects()
        self._digests = reader.get_digests()

    @property
    def raw_string(self):
        return self._raw_string
