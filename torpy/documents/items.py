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

import re
from datetime import datetime

from torpy.crypto_common import b64decode


class ItemType:
    #   "Exactly once": These items MUST occur exactly one time in every
    #       instance of the document type.
    ExactlyOnce = 1

    #     "At most once": These items MAY occur zero or one times in any
    #       instance of the document type, but MUST NOT occur more than once.
    AtMostOnce = 2

    #     "Any number": These items MAY occur zero, one, or more times in any
    #       instance of the document type.
    AnyNumber = 3

    #     "Once or more": These items MUST occur at least once in any instance
    #       of the document type, and MAY occur more.
    OnceOrMore = 4


class ItemParsers:
    @staticmethod
    def split_symbol(line, _reader, split_symbol, fields_names, *_):
        split_line = line.split(split_symbol)
        fields = fields_names
        return dict(zip(fields, split_line))

    @staticmethod
    def by_regex(line, *_):
        return line

    @staticmethod
    def store_string(line, *_):
        return line


class Item:
    def __init__(
        self,
        keyword,
        parse_func=ItemParsers.store_string,
        parse_args=None,
        out_name=None,
        type=ItemType.ExactlyOnce,
        as_list=False,
    ):
        self.keyword = keyword
        self.parse_func = parse_func
        self.parse_args = parse_args or []
        self.out_name = out_name or keyword.replace('-', '_')
        self.type = type
        self.as_list = as_list


class ItemMask(Item):
    def check_item(self, kw):
        return self._mask.match(kw)

    def __init__(self, mask, parse_func, out_name, as_list=False):
        super().__init__('', parse_func=parse_func, out_name=out_name, as_list=as_list)
        self._mask = re.compile(mask)


class ItemObject(Item):
    def __init__(self, object_cls, out_name):
        super().__init__('', parse_func=None, out_name=out_name, as_list=True)
        self.object_cls = object_cls


class ItemDate(Item):
    @staticmethod
    def _get_date(line, *_):
        # Get only two spaced parts
        line = line.split(' ')[:2]
        # 2019-01-01 00:00:00
        return datetime.strptime(' '.join(line), '%Y-%m-%d %H:%M:%S')

    def __init__(self, keyword, out_name=None, type=ItemType.ExactlyOnce):
        super().__init__(keyword, parse_func=ItemDate._get_date, out_name=out_name, type=type)


class ItemInt(Item):
    @staticmethod
    def _get_int(line, *_):
        # Get only one spaced part
        line = line.split(' ')[0]
        return int(line)

    def __init__(self, keyword, out_name=None, type=ItemType.ExactlyOnce):
        super().__init__(keyword, parse_func=ItemInt._get_int, out_name=out_name, type=type)


class ItemEnum(Item):
    def _parse_enum(self, line, *_):
        flags = filter(lambda i: i in self._enum_values, line.split(' '))
        flags = map(lambda i: self._enum_cls[i], flags)
        # reduce(ior, flags)
        return list(flags)

    def __init__(self, keyword, enum_cls, out_name=None, type=ItemType.ExactlyOnce):
        super().__init__(keyword, parse_func=self._parse_enum, out_name=out_name, type=type)
        self._enum_cls = enum_cls
        self._enum_values = dir(self._enum_cls)


class ItemMulti(Item):
    def __init__(self, keyword, ml_name, parse_func=ItemParsers.store_string, out_name=None, as_list=False):
        super().__init__(keyword, parse_func=self._parse, out_name=out_name, as_list=as_list)
        self._args_parse_func = parse_func
        self._ml_name = ml_name.replace(' ', '_')
        self._ml_start_line = f'-----BEGIN {ml_name.upper()}-----'
        self._ml_end_line = f'-----END {ml_name.upper()}-----'

    def _parse(self, line, lines, *_):
        args = self._args_parse_func(line)
        ml = self._read_ml(lines)
        if args:
            args.update({self._ml_name: ml})
        else:
            args = {self.out_name: ml}
        return args

    def _read_ml(self, lines):
        line = next(lines)
        if line != self._ml_start_line:
            raise Exception(f'Begin line for {self.keyword} not found')
        ml = ''
        for line in lines:
            if line == self._ml_end_line:
                break
            ml += line
        return b64decode(ml)
