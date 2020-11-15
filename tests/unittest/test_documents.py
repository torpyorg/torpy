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
import json
import datetime
from enum import Enum
from functools import reduce
from operator import ior

import pytest

from torpy.documents.basics import TorDocumentObject
from torpy.documents.network_status import NetworkStatusDocument, RouterFlags
from torpy.documents.network_status_diff import NetworkStatusDiffDocument
from torpy.documents.dir_key_certificate import DirKeyCertificate, DirKeyCertificateList


def load_text(file_name):
    fpath = os.path.join(os.path.dirname(__file__), 'data', file_name)
    if not os.path.isfile(fpath):
        raise FileNotFoundError(fpath)
    with open(fpath) as f:
        return f.read()


def load_json(file_name):
    try:
        return json.loads(load_text(file_name), object_hook=object_hook)
    except Exception:
        return None


def object_hook(obj):
    _isoformat = obj.get('_isoformat')
    if _isoformat is not None:
        return datetime.datetime.fromisoformat(_isoformat)
    _bytes = obj.get('_bytes')
    if _bytes is not None:
        return bytes.fromhex(_bytes)
    _enum = obj.get('_enum')
    if _enum is not None:
        cls, flags = _enum.split('.')
        flags = map(lambda i: RouterFlags[i], flags.split('|'))
        return reduce(ior, flags)
    return obj


class DocumentEncoder(json.JSONEncoder):
    _excludes = ['_consensus', '_service_key']

    def default(self, obj):
        if isinstance(obj, dict):
            flt_dict = {
                key: value
                for (key, value) in obj.items()
                if key not in DocumentEncoder._excludes
            }
            return flt_dict
        elif isinstance(obj, bytes):
            return {'_bytes': obj.hex()}
        elif isinstance(obj, Enum):
            return {'_enum': str(obj)}
        elif isinstance(obj, (datetime.date, datetime.datetime)):
            return {'_isoformat': obj.isoformat()}
        elif isinstance(obj, TorDocumentObject):
            return self.default(obj._fields)
        else:
            return self.default(obj.__dict__)


def _compare_(o, expected_fields):
    for k, v in expected_fields.items():
        o_val = getattr(o, k)
        if isinstance(o_val, list):
            for i, item in enumerate(o_val):
                _compare(item, expected_fields[k][i])
        elif isinstance(v, dict):
            _compare(o_val, v)
        else:
            assert o_val == v


def _compare(o, expected_fields):
    if isinstance(expected_fields, list):
        for i, item in enumerate(o):
            _compare(item, expected_fields[i])
    elif isinstance(expected_fields, dict):
        for k, v in expected_fields.items():
            if isinstance(o, dict):
                o_val = o[k]
            else:
                o_val = getattr(o, k)
            _compare(o_val, v)
    else:
        assert o == expected_fields


@pytest.mark.parametrize(
    'network_status_raw,expected_fields,digest',
    [
        # Small simple example
        (
            load_text('network_status/consensus'),
            load_json('network_status/consensus.json'),
            '270d2e02d8e6ad83dd87bd56cf8b7874f75063a9',
        ),
        # The same but with extra fields
        (
            load_text('network_status/consensus_extra'),
            load_json('network_status/consensus_extra.json'),
            '38fd029621ca6d3bea5314d8d87c1b374c39a43e',
        ),
        # Real network status example
        (
            load_text('network_status/consensus_real'),
            load_json('network_status/consensus_real.json'),
            '8f4a710a7228ee3ecda56a59a0232a7f8698f514',
        ),
    ],
    ids=['consensus',
         'consensus_extra',
         'consensus_real'],
)
def test_network_status_parse(network_status_raw, expected_fields, digest):
    doc = NetworkStatusDocument(network_status_raw)
    assert doc.raw_string == network_status_raw

    if digest:
        assert doc.get_digest('sha1').hex() == digest

    filename = digest + '.json'
    with open(filename, 'w+') as f:
        json.dump(doc, f, cls=DocumentEncoder, indent=4)
    os.remove(filename)

    if expected_fields:
        _compare(doc, expected_fields)


@pytest.mark.parametrize(
    'doc_raw, diff_raw',
    [
        (load_text('network_status/consensus_real'), load_text('network_status_diff/network-status-diff'))
    ],
    ids=['diff1'],
)
def test_network_status_diff_parse(doc_raw, diff_raw):
    doc = NetworkStatusDocument(doc_raw)
    diff = NetworkStatusDiffDocument(diff_raw)
    assert diff.raw_string == diff_raw
    doc.apply_diff(diff)


@pytest.mark.parametrize(
    'doc_raw, cls',
    [
        (load_text('dir_certs/dir_cert_real'), DirKeyCertificate),
        (load_text('dir_certs/cached-certs'), DirKeyCertificateList)
    ],
    ids=[
        'dir_cert',
        'multiple_certs']
)
def test_dir_cert_parse(doc_raw, cls):
    doc = cls(doc_raw)
    assert doc.raw_string == doc_raw
