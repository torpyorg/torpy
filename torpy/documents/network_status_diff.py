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

from enum import Enum

from torpy.documents import TorDocument
from torpy.documents.items import ItemMask, ItemInt, Item, ItemParsers


class EdActionType(Enum):
    Delete = 'd'
    Append = 'a'
    Change = 'c'


class EdAction:
    def __init__(self, start, end, act_type, data):
        self.start = start
        self.end = end
        self.type = act_type
        self.data = data

    def apply(self, lines, cur_line, cur_end):
        start, end = self.start, self.end
        if start == '$':
            start = end = cur_line
        if end == '$':
            end = cur_end

        if self.type == EdActionType.Append:
            lines[start:start] = self.data
            return start + len(self.data)

        if self.type == EdActionType.Change:
            lines[start - 1:end] = self.data
            return start - 1 + len(self.data)

        if self.type == EdActionType.Delete:
            del lines[start - 1:end]
            return start


class ItemAction(ItemMask):
    @staticmethod
    def _parse_action(line, m, lines, *_):
        if m is None:
            raise ValueError(f'ed line contains invalid command: {line.rstrip()}')
        parts = m.groupdict()
        start = int(parts['start'])
        if start > 2147483647:
            raise ValueError(f'ed line contains line number > INT32_MAX: {start}')
        end = parts['end']
        if end is None:
            end = start
        elif end == '$':
            end = '$'
        else:
            end = int(end)
            if end > 2147483647:
                raise ValueError(f'ed line contains line number > INT32_MAX: {end}')
            if end < start:
                raise ValueError(f'ed line contains invalid range: ({start}, {end})')
        action = EdActionType(parts['action'])

        data = []
        if action in (EdActionType.Append, EdActionType.Change):
            for line in lines:
                if line == '.':
                    break
                data.append(line)

        return EdAction(start, end, action, data)

    def __init__(self, out_name):
        super().__init__(
            r'(?P<start>\d+)(?:,(?P<end>\d+|\$))?(?P<action>[acd])', self._parse_action, out_name, as_list=True
        )


class NetworkStatusDiffDocument(TorDocument):
    DOCUMENT_NAME = 'network_status_diff'

    # The first line is "network-status-diff-version 1" NL
    START_ITEM = ItemInt('network-status-diff-version')

    ITEMS = [
        # The second line is "hash" SP FromDigest SP ToDigest NL
        Item('hash', parse_func=ItemParsers.split_symbol, parse_args=[' ', ['from_digest', 'to_digest']]),
        # Diff Actions
        ItemAction(out_name='actions'),
    ]

    def __init__(self, raw_string):
        super().__init__(raw_string)
