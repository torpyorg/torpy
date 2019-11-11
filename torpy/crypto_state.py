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

import struct
import logging

from torpy.cells import RelayedTorCell
from torpy.utils import to_hex
from torpy.crypto_common import (
    aes_update,
    sha1_stream,
    aes_ctr_decryptor,
    aes_ctr_encryptor,
    sha1_stream_clone,
    sha1_stream_update,
    sha1_stream_finalize,
)

logger = logging.getLogger(__name__)


class CryptoState:
    def __init__(self, data):
        """
        Parse handshake data and create forward/backward digests.

        When used in the ntor handshake, the first HASH_LEN bytes form the
        forward digest Df; the next HASH_LEN form the backward digest Db; the
        next KEY_LEN form Kf, the next KEY_LEN form Kb, and the final
        DIGEST_LEN bytes are taken as a nonce to use in the place of KH in the
        hidden service protocol.  Excess bytes from K are discarded.

        :type data: bytes
        """
        (_fdig, _bdig, _ekey, _dkey) = struct.unpack('!20s20s16s16s', data)

        self._forward_digest = sha1_stream(_fdig)
        self._backward_digest = sha1_stream(_bdig)

        self._forward_cipher = aes_ctr_encryptor(_ekey)
        self._backward_cipher = aes_ctr_decryptor(_dkey)

    def _digesting_func(self, payload):
        self._forward_digest.update(payload)
        digest = self._forward_digest.copy()
        return digest.finalize()[:4]

    def _encrypting_func(self, payload):
        return aes_update(self._forward_cipher, payload)

    def _digest_check_func(self, payload, digest):
        digest_clone = sha1_stream_clone(self._backward_digest)
        sha1_stream_update(digest_clone, payload)
        new_digest = sha1_stream_finalize(digest_clone)[:4]
        if new_digest != digest:
            logger.debug(
                'received cell digest not equal ({!r} != {!r}); payload = {!r}'.format(
                    to_hex(new_digest), to_hex(digest), to_hex(payload)
                )
            )
            return False

        sha1_stream_update(self._backward_digest, payload)
        return True

    def _decrypting_func(self, payload):
        return aes_update(self._backward_cipher, payload)

    def encrypt_forward(self, relay_cell):
        if not relay_cell.digest:
            relay_cell.prepare(self._digesting_func)
        relay_cell.encrypt(self._encrypting_func)

    def decrypt_backward(self, relay_cell):
        # tor ref: relay_decrypt_cell
        encrypted = relay_cell.get_encrypted()
        payload = self._decrypting_func(encrypted)

        # Check if cell is recognized
        header = RelayedTorCell.parse_header(payload)
        if header['is_recognized'] == 0:
            payload_copy = RelayedTorCell.set_header_digest(payload, b'\0' * 4)

            # tor ref: relay_digest_matches
            if self._digest_check_func(payload_copy, header['digest']):
                relay_cell.set_decrypted(**header)
                return
            # Treat as encrypted even if is_recognized flag is zero but digests are not equal:
            # collisions are possible in the encrypted buffer

        # Still encrypted
        relay_cell.set_encrypted(payload)
