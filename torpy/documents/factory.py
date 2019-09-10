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

from torpy.documents import TorDocument


class TorDocumentsFactory:
    @staticmethod
    def parse(raw_string, kwargs=None, possible=None):
        kwargs = kwargs or {}
        possible = possible or TorDocument.__subclasses__()

        for doc_cls in possible:
            if doc_cls.check_start(raw_string):
                return doc_cls(raw_string, **kwargs)

        return None
