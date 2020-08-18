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

from torpy.crypto_common import sha1, aes_update, rsa_encrypt, rsa_load_der, aes_ctr_encryptor

logger = logging.getLogger(__name__)


TOR_DIGEST_LEN = 20


def tor_digest(msg):
    return sha1(msg)


def kdf_tor(shared_secret):
    # tor ref: crypto_expand_key_material_TAP
    t = shared_secret + bytes([0])
    computed_auth = tor_digest(t)
    key_material = b''
    for i in range(1, 5):
        t = shared_secret + bytes([i])
        tsh = tor_digest(t)
        key_material += tsh
    return computed_auth, key_material


# tor-spec.txt 0.3.
KEY_LEN = 16
PK_ENC_LEN = 128
PK_PAD_LEN = 42

PK_DATA_LEN = PK_ENC_LEN - PK_PAD_LEN
PK_DATA_LEN_WITH_KEY = PK_DATA_LEN - KEY_LEN


def hybrid_encrypt(data, rsa_key_der):
    """
    Hybrid encryption scheme.

    Encrypt the entire contents of the byte array "data" with the given "TorPublicKey" according to
    the "hybrid encryption" scheme described in the main Tor specification (tor-spec.txt).
    """
    rsa_key = rsa_load_der(rsa_key_der)

    if len(data) < PK_DATA_LEN:
        return rsa_encrypt(rsa_key, data)

    aes_key_bytes = os.urandom(KEY_LEN)

    # RSA(K | M1) --> C1
    m1 = data[:PK_DATA_LEN_WITH_KEY]
    c1 = rsa_encrypt(rsa_key, aes_key_bytes + m1)

    # AES_CTR(M2) --> C2
    m2 = data[PK_DATA_LEN_WITH_KEY:]
    aes_key = aes_ctr_encryptor(aes_key_bytes)
    c2 = aes_update(aes_key, m2)

    return c1 + c2
