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

# flake8: noqa: E501

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh

from torpy.crypto import kdf_tor
from torpy.crypto_common import dh_shared, dh_public_to_bytes


def to_bytes(hex_str):
    return bytes.fromhex(hex_str)


def simple_urandom(length):
    key = to_bytes('30 DB E6 14 B4 96 05 9F 52 47 8D 36 9B 2A 03 9E')
    assert length == len(key)
    return key


def test_dh():  # noqa: E501
    bend = default_backend()
    p = 179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007
    g = 2

    mini_tor_p_bytes = b'\xff\xff\xff\xff\xff\xff\xff\xff\xc9\x0f\xda\xa2\x21\x68\xc2\x34\xc4\xc6\x62\x8b\x80\xdc\x1c\xd1\x29\x02\x4e\x08\x8a\x67\xcc\x74\x02\x0b\xbe\xa6\x3b\x13\x9b\x22\x51\x4a\x08\x79\x8e\x34\x04\xdd\xef\x95\x19\xb3\xcd\x3a\x43\x1b\x30\x2b\x0a\x6d\xf2\x5f\x14\x37\x4f\xe1\x35\x6d\x6d\x51\xc2\x45\xe4\x85\xb5\x76\x62\x5e\x7e\xc6\xf4\x4c\x42\xe9\xa6\x37\xed\x6b\x0b\xff\x5c\xb6\xf4\x06\xb7\xed\xee\x38\x6b\xfb\x5a\x89\x9f\xa5\xae\x9f\x24\x11\x7c\x4b\x1f\xe6\x49\x28\x66\x51\xec\xe6\x53\x81\xff\xff\xff\xff\xff\xff\xff\xff'
    assert p.to_bytes(128, 'big') == mini_tor_p_bytes

    dh_parameters_numbers = dh.DHParameterNumbers(p, g)

    dh_private_bytes = to_bytes(
        '81 2A 69 3A CD 75 6B 3F 3E 9A 8C 64 A4 ED 8C B5 2A 43 8B E7 6B 0D FB F5 CB 0D 70 E1 DB 2A 5F 57 4F 36 7D F1 B0 D1 E5 57 32 57 92 03 E4 0C 08 EF BA 7B 82 25 10 00 94 F0 3A E9 3F 2C AF 24 D6 FB A7 E0 DE 97 18 B5 DB E9 15 44 69 F8 CA 42 E8 87 18 16 BB F6 F8 8E D0 C9 B1 41 D4 02 02 E8 1A EC B3 E2 EB 06 04 86 EB 3D 6E A4 5E D7 4C ED EB B5 C6 7A A7 4F 13 99 D4 50 C8 BA 1E 9B 79 66 36 1D'
    )
    dh_private_x = int.from_bytes(dh_private_bytes, 'big')

    dh_public_bytes = to_bytes(
        '8F 61 59 22 DC 09 BF AB EF 79 3B 2F 3C 6D D3 51 2D FB 29 41 B2 45 59 B7 BF 64 17 41 9B 17 5F F3 7C 5E C8 A8 A9 87 19 72 4D 94 8A 7F 3A 7B D8 30 8C F3 79 88 4F 72 55 DA 7F A7 DC 93 26 C4 16 92 DB 14 C5 34 94 5C 48 4A 0F 54 39 EF 77 8F D1 64 EF BE 0F B4 55 B8 C1 DF DA 9F D5 60 03 B2 C5 34 4C 46 23 00 A8 89 47 F0 2F 5A 26 FC 5E 1A BB 63 49 25 19 BB BD 5F 69 6E 7D A0 00 50 28 06 21 CC'
    )
    dh_public_y = int.from_bytes(dh_public_bytes, 'big')

    dh_public_num = dh.DHPublicNumbers(dh_public_y, dh_parameters_numbers)
    dh_public = dh_public_num.public_key(bend)

    # Check public serialization
    assert dh_public_to_bytes(dh_public) == dh_public_bytes

    dh_private_num = dh.DHPrivateNumbers(dh_private_x, dh_public_num)
    dh_private = dh_private_num.private_key(bend)

    other_public_bytes = to_bytes(
        '69 47 FC C9 54 60 AE F6 F6 99 C1 E2 FA 9A 6F FA A2 76 FD 0B 89 6C CD 6F 0C 73 99 20 F6 38 64 83 54 09 61 F4 48 F4 90 9D 41 BB D7 72 E5 B0 C1 B7 9D B2 DD ED E2 C8 50 D8 49 EE 61 DA D0 6E 73 02 4B B4 A9 66 CE 83 AF 97 01 2D 08 9C 83 63 9A AB 33 D9 0C 80 2B 26 E9 6B D0 C9 9D 53 FF 53 C0 24 8F 73 5A 71 15 CC 6D 20 92 80 00 4E EA FD 11 25 C9 74 44 8A 86 3F 27 BC 5F 4C B3 D7 98 DB 7A 7F'
    )
    dh_other_public_y = int.from_bytes(other_public_bytes, 'big')
    dh_other_public_num = dh.DHPublicNumbers(dh_other_public_y, dh_parameters_numbers)
    dh_other_public = dh_other_public_num.public_key(bend)

    # Check shared
    shared = dh_shared(dh_private, dh_other_public)
    expected_shared = to_bytes(
        'CF 67 62 D4 65 96 A0 B0 E0 A9 C2 32 7E 09 E5 B4 81 6B 30 6B 9B 7B 75 65 BE 91 0E 59 F0 96 D8 95 AA 51 89 AE CB 07 50 DE E7 9B 53 A9 29 06 16 65 6C F1 F1 4D F8 B9 94 23 5E FE C5 64 83 F2 40 AD 92 7D 63 76 47 37 6F DE 67 16 CE 38 B7 5C BD 36 C6 99 00 00 09 DE 6E E2 5A 9D 9B BB EC 71 43 1C 41 1A 39 C0 C5 21 88 A0 BB 0E C4 BF 46 F3 30 FC 47 5B 05 45 F9 49 59 3B 63 1C ED C0 EF 21 F0 44'
    )
    assert shared == expected_shared

    # Check derived
    computed_auth, key_material = kdf_tor(shared)
    expected_derived = to_bytes(
        '01 41 3D 3A 4A 06 55 4E 27 76 42 EA D4 44 F5 D8 A3 50 CD DD 60 2B 4D BD 97 76 7C CE DF E9 05 29 40 C6 14 EA E0 05 40 2D 08 8C B9 34 BD 24 16 E9 97 E6 8A 76 C1 FB C9 25 EA 77 D5 F6 19 9C 0E 65 A1 C2 D9 9E 70 B4 39 7F 60 C2 9D 8C A8 BE C0 E3 77 7D 05 FC A8 5A 6C F2 BD 46 05 CB 83 37 B4 96 4A 6C 2F 8F'
    )
    assert computed_auth + key_material == expected_derived
