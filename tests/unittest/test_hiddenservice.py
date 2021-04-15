import pytest

from torpy.hiddenservice import HiddenService


@pytest.mark.parametrize(
    'onion_hostname, expected_result',
    [
        ('facebookcorewwwi.onion',
         ('facebookcorewwwi', b'(\x04@\xb9\xca\x13\xa2KZ\xc8', None)),
        ('sss.subdomain.facebookcorewwwi.onion',
         ('facebookcorewwwi', b'(\x04@\xb9\xca\x13\xa2KZ\xc8', None)),
        ('5gdvpfoh6kb2iqbizb37lzk2ddzrwa47m6rpdueg2m656fovmbhoptqd.onion',
         ('5gdvpfoh6kb2iqbizb37lzk2ddzrwa47m6rpdueg2m656fovmbhoptqd', None,
          b'\xe9\x87W\x95\xc7\xf2\x83\xa4@(\xc8w\xf5\xe5Z\x18\xf3\x1b\x03\x9fg\xa2\xf1\xd0\x86\xd3=\xdf\x15\xd5`N')),
        ('subd.5gdvpfoh6kb2iqbizb37lzk2ddzrwa47m6rpdueg2m656fovmbhoptqd.onion',
         ('5gdvpfoh6kb2iqbizb37lzk2ddzrwa47m6rpdueg2m656fovmbhoptqd', None,
          b'\xe9\x87W\x95\xc7\xf2\x83\xa4@(\xc8w\xf5\xe5Z\x18\xf3\x1b\x03\x9fg\xa2\xf1\xd0\x86\xd3=\xdf\x15\xd5`N')),
    ]
)
def test_parse_onion(onion_hostname, expected_result):
    result = HiddenService.parse_onion(onion_hostname)
    assert result == expected_result
