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

import math
import time
import struct
import logging
from base64 import b32decode, b32encode
from typing import TYPE_CHECKING

from torpy.cells import CellRelayRendezvous2
from torpy.utils import AuthType
from torpy.parsers import IntroPointParser, HSDescriptorParser
from torpy.crypto_common import sha1, aes_update, aes_ctr_decryptor, b64decode, curve25519_public_from_bytes

if TYPE_CHECKING:
    from torpy.circuit import TorCircuit

logger = logging.getLogger(__name__)


# tor ref: handle_control_hsfetch
# tor ref: connection_ap_handle_onion
class HiddenService:
    # Length of 'y' portion of 'y.onion' URL.
    REND_SERVICE_ID_LEN_BASE32 = 16
    # Length of a binary-encoded rendezvous service ID.
    REND_SERVICE_ID_LEN = 10

    # ...
    ED25519_PUBKEY_LEN = 32

    # The amount of bytes we use from the address checksum.
    HS_SERVICE_ADDR_CHECKSUM_LEN_USED = 2

    # Length of the binary encoded service address which is of course before the
    # base32 encoding. Construction is:
    #    PUBKEY || CHECKSUM || VERSION
    # with 1 byte VERSION and 2 bytes CHECKSUM. The following is 35 bytes.
    HS_SERVICE_ADDR_LEN = (ED25519_PUBKEY_LEN + HS_SERVICE_ADDR_CHECKSUM_LEN_USED + 1)

    # Length of 'y' portion of 'y.onion' URL. This is base32 encoded and the
    # length ends up to 56 bytes (not counting the terminated NUL byte.)
    HS_SERVICE_ADDR_LEN_BASE32 = math.ceil(HS_SERVICE_ADDR_LEN * 8 / 5)

    HS_NO_AUTH = (None, AuthType.No)

    def __init__(self, onion_address, descriptor_cookie=None, auth_type=AuthType.No):
        self._onion_address, self._permanent_id, onion_identity_pk = self.parse_onion(onion_address)
        self._onion_identity_pk = curve25519_public_from_bytes(onion_identity_pk) if onion_identity_pk else None
        if self._onion_identity_pk:
            raise Exception('v3 onion hidden service not supported yet')
        self._descriptor_cookie = b64decode(descriptor_cookie) if descriptor_cookie else None
        self._auth_type = auth_type
        if descriptor_cookie and auth_type == AuthType.No:
            raise RuntimeError('You must specify auth type')
        if not descriptor_cookie and auth_type != AuthType.No:
            raise RuntimeError('You must specify descriptor cookie')

    @staticmethod
    def normalize_onion(onion_address):
        if onion_address.endswith('.onion'):
            onion_address = onion_address[:-6].rsplit('.', 1)[-1]

        if len(onion_address) != HiddenService.REND_SERVICE_ID_LEN_BASE32 and \
           len(onion_address) != HiddenService.HS_SERVICE_ADDR_LEN_BASE32:
            raise Exception(f'Unknown onion address: {onion_address}')

        return onion_address

    @staticmethod
    def parse_onion(onion_address):
        onion_address = HiddenService.normalize_onion(onion_address)

        if len(onion_address) == HiddenService.REND_SERVICE_ID_LEN_BASE32:
            permanent_id = b32decode(onion_address.upper())
            assert len(permanent_id) == HiddenService.REND_SERVICE_ID_LEN, 'You must specify valid V2 onion hostname'
            return onion_address, permanent_id, None
        elif len(onion_address) == HiddenService.HS_SERVICE_ADDR_LEN_BASE32:
            # tor ref: hs_parse_address
            decoded = b32decode(onion_address.upper())
            pubkey = decoded[:HiddenService.ED25519_PUBKEY_LEN]
            # checksum decoded[self.ED25519_PUBKEY_LEN:self.ED25519_PUBKEY_LEN + self.HS_SERVICE_ADDR_CHECKSUM_LEN_USED]
            # version decoded[self.ED25519_PUBKEY_LEN + self.HS_SERVICE_ADDR_CHECKSUM_LEN_USED:]
            return onion_address, None, pubkey
            # fetch_v3_desc
            # pick_hsdir_v3
            # directory_launch_v3_desc_fetch

    @property
    def onion(self):
        return self._onion_address

    @property
    def hostname(self):
        return self._onion_address + '.onion'

    @property
    def permanent_id(self):
        """service-id or permanent-id."""
        return self._permanent_id

    @property
    def descriptor_cookie(self):
        return self._descriptor_cookie

    @property
    def auth_type(self):
        return self._auth_type

    def _get_secret_id(self, replica):
        """
        Get secret_id by replica number.

        rend-spec.txt
        1.3.

        "time-period" changes periodically as a function of time and
        "permanent-id". The current value for "time-period" can be calculated
        using the following formula:

          time-period = (current-time + permanent-id-byte * 86400 / 256)
                          / 86400
        """
        # tor ref: get_secret_id_part_bytes
        permanent_byte = self._permanent_id[0]
        time_period = int((int(time.time()) + (permanent_byte * 86400 / 256)) / 86400)
        if self._descriptor_cookie and self._auth_type == AuthType.Stealth:
            buff = struct.pack('!I16sB', time_period, self._descriptor_cookie, replica)
        else:
            buff = struct.pack('!IB', time_period, replica)
        return sha1(buff)

    def get_descriptor_id(self, replica):
        # tor ref: rend_compute_v2_desc_id
        # Calculate descriptor ID: H(permanent-id | secret-id-part)
        buff = self._permanent_id + self._get_secret_id(replica)
        return sha1(buff)


class HiddenServiceConnector:
    def __init__(self, circuit, consensus):
        self._circuit = circuit
        self._consensus = consensus

    def get_responsibles_dir(self, hidden_service):
        for i, responsible_router in enumerate(self._consensus.get_responsibles(hidden_service)):
            replica = 1 if i >= 3 else 0
            yield ResponsibleDir(responsible_router, replica, self._circuit, self._consensus)


class EncPointsBuffer:
    # /** Length of our symmetric cipher's keys of 128-bit. */
    CIPHER_KEY_LEN = 16
    # /** Length of our symmetric cipher's IV of 128-bit. */
    CIPHER_IV_LEN = 16
    # /** Length of our symmetric cipher's keys of 256-bit. */
    CIPHER256_KEY_LEN = 32
    # /** Length of client identifier in encrypted introduction points for hidden
    #  * service authorization type 'basic'. */
    REND_BASIC_AUTH_CLIENT_ID_LEN = 4
    # /** Multiple of the number of clients to which the real number of clients
    #  * is padded with fake clients for hidden service authorization type
    #  * 'basic'. */
    REND_BASIC_AUTH_CLIENT_MULTIPLE = 16
    # /** Length of client entry consisting of client identifier and encrypted
    #  * session key for hidden service authorization type 'basic'. */
    REND_BASIC_AUTH_CLIENT_ENTRY_LEN = REND_BASIC_AUTH_CLIENT_ID_LEN + CIPHER_KEY_LEN

    def __init__(self, crypted_data):
        self._crypted_data = crypted_data
        assert len(crypted_data) > 2, 'Size of crypted data too small'
        self._auth_type = int(crypted_data[0])
        # fmt: off
        self._auth_to_func = {AuthType.Basic: self._decrypt_basic,
                              AuthType.Stealth: self._decrypt_stealth}
        # fmt: on

    @property
    def auth_type(self):
        return self._auth_type

    def decrypt(self, descriptor_cookie):
        # tor ref: rend_decrypt_introduction_points
        return self._auth_to_func[self._auth_type](descriptor_cookie)

    def _decrypt_basic(self, descriptor_cookie):
        assert self._crypted_data[0] == AuthType.Basic
        block_count = self._crypted_data[1]
        entries_len = block_count * self.REND_BASIC_AUTH_CLIENT_MULTIPLE * self.REND_BASIC_AUTH_CLIENT_ENTRY_LEN
        assert len(self._crypted_data) > 2 + entries_len + self.CIPHER_IV_LEN, 'Size of crypted data too small'
        iv = self._crypted_data[2 + entries_len:2 + entries_len + self.CIPHER_IV_LEN]
        client_id = sha1(descriptor_cookie + iv)[:4]
        session_key = self._get_session_key(self._crypted_data[2:2 + entries_len], descriptor_cookie, client_id)
        d = aes_ctr_decryptor(session_key, iv)
        data = self._crypted_data[2 + entries_len + self.CIPHER_IV_LEN:]
        return d.update(data)

    def _get_session_key(self, data, descriptor_cookie, client_id):
        pos = 0
        d = aes_ctr_decryptor(descriptor_cookie)
        while pos < len(data):
            if data[pos:pos + self.REND_BASIC_AUTH_CLIENT_ID_LEN] == client_id:
                start_key_pos = pos + self.REND_BASIC_AUTH_CLIENT_ID_LEN
                end_key_pos = start_key_pos + self.CIPHER_KEY_LEN
                enc_session_key = data[start_key_pos:end_key_pos]
                return aes_update(d, enc_session_key)
            pos += self.REND_BASIC_AUTH_CLIENT_ENTRY_LEN
        raise Exception('Session key for client {!r} not found'.format(client_id))

    def _decrypt_stealth(self, descriptor_cookie):
        assert len(self._crypted_data) > 2 + self.CIPHER_IV_LEN, 'Size of encrypted data is too small'
        assert self._crypted_data[0] == AuthType.Stealth
        iv = self._crypted_data[1:1 + self.CIPHER_IV_LEN]
        d = aes_ctr_decryptor(descriptor_cookie, iv)
        data = self._crypted_data[1 + self.CIPHER_IV_LEN:]
        return d.update(data)


class DescriptorNotAvailable(Exception):
    """Descriptor not found."""


class ResponsibleDir:
    def __init__(self, router, replica, circuit, consensus):
        self._router = router
        self._replica = replica
        self._circuit = circuit
        self._consensus = consensus

    @property
    def replica(self):
        return self._replica

    def get_introductions(self, hidden_service):
        descriptor_id = hidden_service.get_descriptor_id(self.replica)
        response = self._fetch_descriptor(descriptor_id)
        for intro_point in self._get_intro_points(response, hidden_service.descriptor_cookie):
            yield intro_point

    def _fetch_descriptor(self, descriptor_id):
        # tor ref: rend_client_fetch_v2_desc
        # tor ref: fetch_v3_desc

        logger.info('Create circuit for hsdir')
        with self._circuit.create_new_circuit(extend_routers=[self._router]) as directory_circuit:
            assert directory_circuit.nodes_count == 2

            with directory_circuit.create_dir_client() as dir_client:
                # tor ref: directory_send_command (DIR_PURPOSE_FETCH_RENDDESC_V2)
                descriptor_id_str = b32encode(descriptor_id).decode().lower()
                descriptor_path = f'/tor/rendezvous2/{descriptor_id_str}'

                status, response = dir_client.get(descriptor_path)
                response = response.decode()
                if status != 200:
                    logger.error('No valid response from hsdir. Status = %r. Body: %r', status, response)
                    raise DescriptorNotAvailable("Couldn't fetch descriptor")

                return response

    def _info_to_router(self, intro_point_info):
        onion_router = self._consensus.get_router(intro_point_info['introduction_point'])
        onion_router.service_key = intro_point_info['service_key']
        onion_router.onion_key = intro_point_info['onion_key']
        return onion_router

    def _get_intro_points(self, response, descriptor_cookie):
        intro_points_raw_base64 = HSDescriptorParser.parse(response)
        intro_points_raw = b64decode(intro_points_raw_base64)

        # Check whether it's encrypted
        if intro_points_raw[0] == AuthType.Basic or intro_points_raw[0] == AuthType.Stealth:
            if not descriptor_cookie:
                raise Exception('Hidden service needs descriptor_cookie for authorization')
            enc_buff = EncPointsBuffer(intro_points_raw)
            intro_points_raw = enc_buff.decrypt(descriptor_cookie)
        elif descriptor_cookie:
            logger.warning("Descriptor cookie was specified but hidden service hasn't encrypted intro points")

        if not intro_points_raw.startswith(b'introduction-point '):
            raise Exception('Unknown introduction point data received')

        intro_points_raw = intro_points_raw.decode()
        intro_points_info_list = IntroPointParser.parse(intro_points_raw)

        for intro_point_info in intro_points_info_list:
            router = self._info_to_router(intro_point_info)
            yield IntroductionPoint(router, self._circuit)

    def __str__(self):
        """Format ResponsibleDir string representation."""
        return 'ResponsibleDir {}'.format(self._router)


class IntroductionPoint:
    def __init__(self, router, circuit: 'TorCircuit'):
        self._introduction_router = router
        self._circuit = circuit

    def connect(self, hidden_service, rendezvous_cookie):
        # Waiting for CellRelayRendezvous2 in our main circuit
        with self._circuit.create_waiter(CellRelayRendezvous2) as w:
            # Create introduction point circuit
            with self._circuit.create_new_circuit(extend_routers=[self._introduction_router]) as intro_circuit:
                assert intro_circuit.nodes_count == 2

                # TODO: tor ref: v3 hs_client send_introduce1
                # Send Introduce1
                extend_node = intro_circuit.rendezvous_introduce(
                    self._circuit,
                    rendezvous_cookie,
                    hidden_service.auth_type,
                    hidden_service.descriptor_cookie,
                )

                rendezvous2_cell = w.get(timeout=10)
                extend_node.complete_handshake(rendezvous2_cell.handshake_data)
                return extend_node
