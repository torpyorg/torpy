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

from torpy.documents.basics import TorDocument, TorDocumentObject
from torpy.documents.items import Item, ItemDate, ItemInt, ItemMulti, ItemObject

logger = logging.getLogger(__name__)


class DirKeyCertificateObject(TorDocumentObject):

    START_ITEM = ItemInt('dir-key-certificate-version')

    ITEMS = [
        # fingerprint 14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4
        Item('fingerprint'),
        # dir-key-published 2019-06-01 00:00:00
        ItemDate('dir-key-published'),
        # dir-key-expires 2019-11-01 00:00:00
        ItemDate('dir-key-expires'),
        ItemMulti('dir-identity-key', 'rsa public key'),
        ItemMulti('dir-signing-key', 'rsa public key'),
        ItemMulti('dir-key-crosscert', 'id signature'),
        ItemMulti('dir-key-certification', 'signature'),
    ]


class DirKeyCertificate(TorDocument, DirKeyCertificateObject):
    DOCUMENT_NAME = 'dir_key_certificate'


class DirKeyCertificateList(TorDocument):
    DOCUMENT_NAME = 'dir_key_certificates'

    START_ITEM = ''

    ITEMS = [ItemObject(DirKeyCertificateObject, out_name='certs')]

    def find(self, identity):
        return next((cert for cert in self.certs if cert.fingerprint == identity), None)
