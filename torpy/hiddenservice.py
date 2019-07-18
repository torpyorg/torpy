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
import time

from base64 import b32decode, b32encode, b64decode, b64encode

from torpy.cells import *
from torpy.parsers import HSDescriptorParser, IntroPointParser
from torpy.crypto_common import *
from torpy.http.client import HttpClient
from torpy.utils import AuthType


# ref tor: connection_ap_handle_onion
class HiddenService:
    def __init__(self, onion, descriptor_cookie=None, auth_type=AuthType.No):
        assert onion.endswith('.onion'), 'You must specify valid onion hostname'
        # TODO: only v2 onion
        self._onion = onion[:-6][-16:]
        self._rendezvous_cookie = os.urandom(20)
        self._descriptor_cookie = b64decode(descriptor_cookie) if descriptor_cookie else None
        self._auth_type = auth_type
        if descriptor_cookie and auth_type == AuthType.No:
            raise RuntimeError('You must specify auth type')
        if not descriptor_cookie and auth_type != AuthType.No:
            raise RuntimeError('You must specify descriptor cookie')

    @property
    def onion(self):
        return self._onion

    @property
    def hostname(self):
        return self._onion + '.onion'

    @property
    def permanent_id(self):
        return b32decode(self._onion.upper())

    @property
    def descriptor_cookie(self):
        return self._descriptor_cookie

    @property
    def auth_type(self):
        return self._auth_type

    @property
    def rendezvous_cookie(self):
        return self._rendezvous_cookie

    def _get_secret_id(self, replica):
        """
            rend-spec.txt
            1.3.

            "time-period" changes periodically as a function of time and
            "permanent-id". The current value for "time-period" can be calculated
            using the following formula:

              time-period = (current-time + permanent-id-byte * 86400 / 256)
                              / 86400
        """
        # tor ref: get_secret_id_part_bytes
        permanent_byte = self.permanent_id[0]
        time_period = int((int(time.time()) + (permanent_byte * 86400 / 256)) / 86400)
        if self._descriptor_cookie and self._auth_type == AuthType.Stealth:
            buff = struct.pack('!I16sB', time_period, self._descriptor_cookie, replica)
        else:
            buff = struct.pack('!IB', time_period, replica)
        return sha1(buff)

    def get_descriptor_id(self, replica):
        # tor ref: rend_compute_v2_desc_id
        secret_id = self._get_secret_id(replica)
        buff = self.permanent_id + secret_id
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
        self._auth_to_func = {AuthType.Basic: self._decrypt_basic,
                              AuthType.Stealth: self._decrypt_stealth}

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
        session_key = self._get_session_key(self._crypted_data[2:2+entries_len], descriptor_cookie, client_id)
        d = aes_ctr_decryptor(session_key, iv)
        data = self._crypted_data[2 + entries_len + self.CIPHER_IV_LEN:]
        return d.update(data)

    def _get_session_key(self, data, descriptor_cookie, client_id):
        pos = 0
        d = aes_ctr_decryptor(descriptor_cookie)
        while pos < len(data):
            if data[pos:pos+self.REND_BASIC_AUTH_CLIENT_ID_LEN] == client_id:
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
    """Descriptor not found"""


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

        logger.info("Create circuit for hsdir")
        with self._circuit.create_new_circuit() as directory_circuit:
            directory_circuit.extend(self._router)
            assert directory_circuit.nodes_count == 2

            with directory_circuit.create_stream() as stream:
                stream.connect_dir()

                descriptor_id_str = b32encode(descriptor_id).decode().lower()

                # tor ref: directory_send_command (DIR_PURPOSE_FETCH_RENDDESC_V2)
                descriptor_path = '/tor/rendezvous2/{}'.format(descriptor_id_str)

                http_client = HttpClient(stream)
                response = http_client.get(self._router.ip, descriptor_path).decode()
                if response and ' 200 OK' in response:
                    return response
                else:
                    logger.error('Response from hsdir: %r', response)
                    raise DescriptorNotAvailable("Can't fetch descriptor")

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
        return 'ResponsibleDir {}'.format(self._router)


class IntroductionPoint:
    def __init__(self, router, circuit):
        self._introduction_router = router
        self._circuit = circuit

    def connect(self, hidden_service):
        # Waiting for CellRelayRendezvous2 in our main circuit
        with self._circuit._create_waiter(CellRelayRendezvous2) as w:
            # Create introduction point circuit
            with self._circuit.create_new_circuit() as intro_circuit:
                intro_circuit.extend(self._introduction_router)
                assert intro_circuit.nodes_count == 2

                # Send Introduce1
                extend_node = intro_circuit._rendezvous_introduce(self._circuit,
                                                                  hidden_service.rendezvous_cookie,
                                                                  hidden_service.auth_type,
                                                                  hidden_service.descriptor_cookie)

                rendezvous2_cell = w.get(timeout=10)
                extend_node.complete_handshake(rendezvous2_cell.handshake_data)
                return extend_node
