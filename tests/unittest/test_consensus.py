import pytest

from torpy.consesus import DirectoryServer, DirectoryFlags, RouterFlags


@pytest.mark.parametrize(
    'line, result',
    [
        (
                '"moria1 orport=9101 v3ident=D586D18309DED4CD6D57C18FDB97EFA96D330566 128.31.0.39:9131 9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31"',  # noqa: E501, E126
                {'_nickname': 'moria1', '_fingerprint': b'\x96\x95\xdf\xc3_\xfe\xb8a2\x9b\x9f\x1a\xb0LF9p \xce1',
                 '_digest': None, '_ip': '128.31.0.39', '_or_port': 9101, '_dir_port': 9131, '_version': None,
                 '_flags': [RouterFlags.Authority], '_consensus': None, '_service_key': None,
                 '_dir_flags': DirectoryServer.AUTH_FLAGS, '_v3ident': 'D586D18309DED4CD6D57C18FDB97EFA96D330566',
                 '_ipv6': None,
                 '_bridge': False}),
        (
                '"tor26 orport=443 v3ident=14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 ipv6=[2001:858:2:2:aabb:0:563b:1526]:443 86.59.21.38:80 847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D"',  # noqa: E501
                {'_nickname': 'tor26', '_fingerprint': b'\x84{\x1f\x85\x03D\xd7\x87d\x91\xa5H\x92\xf9\x04\x93NN\xb8]',
                 '_digest': None, '_ip': '86.59.21.38', '_or_port': 443, '_dir_port': 80, '_version': None,
                 '_flags': [RouterFlags.Authority], '_consensus': None, '_service_key': None,
                 '_dir_flags': DirectoryServer.AUTH_FLAGS, '_v3ident': '14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4',
                 '_ipv6': '[2001:858:2:2:aabb:0:563b:1526]:443', '_bridge': False}),
        (
                '"dizum orport=443 v3ident=E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58 45.66.33.45:80 7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755"',  # noqa: E501
                {'_nickname': 'dizum', '_fingerprint': b'~\xa6\xea\xd6\xfd\x83\x08<S\x8fD\x03\x8b\xbf\xa0wX}\xd7U',
                 '_digest': None, '_ip': '45.66.33.45', '_or_port': 443, '_dir_port': 80, '_version': None,
                 '_flags': [RouterFlags.Authority], '_consensus': None, '_service_key': None,
                 '_dir_flags': DirectoryServer.AUTH_FLAGS, '_v3ident': 'E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58',
                 '_ipv6': None, '_bridge': False}),
        (
                '"Serge orport=9001 bridge 66.111.2.131:9030 BA44 A889 E64B 93FA A2B1 14E0 2C2A 279A 8555 C533"',
                {'_nickname': 'Serge', '_fingerprint': b"\xbaD\xa8\x89\xe6K\x93\xfa\xa2\xb1\x14\xe0,*'\x9a\x85U\xc53",
                 '_digest': None, '_ip': '66.111.2.131', '_or_port': 9001, '_dir_port': 9030, '_version': None,
                 '_flags': [RouterFlags.Authority], '_consensus': None, '_service_key': None,
                 '_dir_flags': DirectoryFlags.BRIDGE_DIRINFO, '_v3ident': None, '_ipv6': None, '_bridge': True}),
        (
                '"gabelmoo orport=443 v3ident=ED03BB616EB2F60BEC80151114BB25CEF515B226 ipv6=[2001:638:a000:4140::ffff:189]:443 131.188.40.189:80 F204 4413 DAC2 E02E 3D6B CF47 35A1 9BCA 1DE9 7281"',  # noqa: E501
                {'_nickname': 'gabelmoo',
                 '_fingerprint': b'\xf2\x04D\x13\xda\xc2\xe0.=k\xcfG5\xa1\x9b\xca\x1d\xe9r\x81', '_digest': None,
                 '_ip': '131.188.40.189', '_or_port': 443, '_dir_port': 80, '_version': None,
                 '_flags': [RouterFlags.Authority], '_consensus': None, '_service_key': None,
                 '_dir_flags': DirectoryServer.AUTH_FLAGS, '_v3ident': 'ED03BB616EB2F60BEC80151114BB25CEF515B226',
                 '_ipv6': '[2001:638:a000:4140::ffff:189]:443', '_bridge': False})
    ],
    ids=[
        'moria1',
        'tor26',
        'dizum',
        'Serge',
        'gabelmoo'
    ]
)
def test_dir_cert_parse(line, result):
    ds = DirectoryServer.from_authority_str(line)
    assert vars(ds) == result
