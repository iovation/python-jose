import json

import pytest
import six

import jose.backends
from jose import jwe
from jose.constants import ALGORITHMS, ZIPS
from jose.exceptions import JWEParseError
from jose.jwk import AESKey
from jose.jwk import RSAKey
from jose.utils import base64url_decode

backends = []
try:
    import jose.backends.cryptography_backend  # noqa E402
    backends.append(jose.backends.cryptography_backend)
except ImportError:
    pass
try:
    import jose.backends.pycrypto_backend  # noqa E402
    backends.append(jose.backends.pycrypto_backend)
except ImportError:
    pass
import jose.backends.native  # noqa E402

try:
    from jose.backends.rsa_backend import RSAKey as RSABackendRSAKey
except ImportError:
    RSABackendRSAKey = None

backends.append(jose.backends.native)

PRIVATE_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3AyQGW/Q8AKJH2Mfjv1c67iYcwIn+Z2tpqHDQQV9CfSx9CMs
+Zg2buopXJ7AWd03ZR08g9O2bmlJPIQV1He3vfzZH9+6aJAQLJ+VzpME2sXl5Boa
yla1JjyoH7ix/i02QHDTVClDMb6dy0rMVpc7cBxwgX54fcR5x3AMscYCTQrhQc7q
YRzoLTfP9lGJT1DgyGcOt4paa77z4uqqaQxQ4QqxM9in3DU0mzVxXigHVakjiS6v
kSNEhSl+VLIp1sHiOhOSpcxWkhTikjm+XpwE5H0L9I1mQ2e2nTvX7uADg/pgFMy0
uP833rQzTxNqTTPJZFLtLkTyq1Hr2MUeQ3dRNQIDAQABAoIBAFK9+pVGAVeubGc7
+4rl5EHSqKheQC/RRZGps+TILotG0n9NlsTHong0XpcwLn3b+89unemn+yorNtml
hRveZF3xLKealdppiVtuKoOBrsqgrWAHHNnGntkg58r9xRghYgv7IMu9tEGJPoZJ
uuo4daYjW36l0qLf9Ta0AGH8ZbMX2LnNO+r4EQmZ1YJShEYOS94WJnFB7XuZ/bQH
AI3IRPkQvXQNq1nnMxhAj91hOhJvTVCS04yVVzMkntcpeNP7pc7ARtSA5IepJvdK
HbcoSQ1aIK/NPkhiDs/KOoWdnB8Mqr3fXFTVJ3/YTJKwODugJ5QCbSyIC8JewgIn
d6mA6iECgYEA7028RNk65c5NRkv6rkveTT1ybrvYUUO/pbAlS4MqZmtx69n4LFrW
qicXw7sJd+O8emyvF3xHPAfVviJKg6yudtI0nM9WUuOgKr+qoKRWJMpspXdpjTXs
AQXrFAJjrDIFujsbnRmT2nbRX8nSBWvI5oSG4JqILWYs0OdchIkPo0kCgYEA62bq
mjnlz7Mqvznf8b9jOSEJKub81aUz/fK62gXcEdvffUdlDecAzotjryI678TvEBpI
w1rmHLND60o+Lczd3quyEPQfYrf8P4/6sqGfE/QtB7zKR1bXmkV0dNlr9h6zpm/Y
BpLNiqr3Ntf4OCkKiD6ch+sZ4NjKBCwzodolUo0CgYEAk/PEzfBcqM5nGmpJX8/K
bojqIiqDcKLpb4A7XreG1HHjqkVGWe4DwImQ+NO/497qnepqSqPsyuGxNe+vkD+I
UjBelQDfxzmywhtkXBOeqvp4N8lfeg33jx5gnCtqAoGe5ug6h2PT9QL3Kjj2X6Gn
QVZ4qY8BWMhONw6ENfEjuPkCgYBP0ps05vMdpgSVyXs9z4dG5QPlz2Pm0lk6AKgJ
rDj+uU8kfSQwPafRYgTQa0wO5/mkvTT1QYqMKuGaFJfXEgQeMJx2EUHfSMI5j4oU
LqfxrTfjysnQvQrpHioqQVvRnoGOq5hWSkt2fRjNORjLemc+4fRURo2E6B5Aofh0
JrPHNQKBgBGYzDGJyFnu7GYTby18aPNkQYweNDM6aZ/tUN8yZ4ryq7QnodiKLe2b
VxSr8Y+1w4xRjN67PGrS3IpQX9CAoTqyBN7VLhuq/mixOPccmo/5ui3fig/WEYwK
+ox4tfIuhfmskPNS235vLwbNIBkzP3PWVM5Chq1pEnHQUeiZq3U+
-----END RSA PRIVATE KEY-----
"""

PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3AyQGW/Q8AKJH2Mfjv1c
67iYcwIn+Z2tpqHDQQV9CfSx9CMs+Zg2buopXJ7AWd03ZR08g9O2bmlJPIQV1He3
vfzZH9+6aJAQLJ+VzpME2sXl5Boayla1JjyoH7ix/i02QHDTVClDMb6dy0rMVpc7
cBxwgX54fcR5x3AMscYCTQrhQc7qYRzoLTfP9lGJT1DgyGcOt4paa77z4uqqaQxQ
4QqxM9in3DU0mzVxXigHVakjiS6vkSNEhSl+VLIp1sHiOhOSpcxWkhTikjm+XpwE
5H0L9I1mQ2e2nTvX7uADg/pgFMy0uP833rQzTxNqTTPJZFLtLkTyq1Hr2MUeQ3dR
NQIDAQAB
-----END PUBLIC KEY-----
"""

OCT_128_BIT_KEY = b"\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xce"
OCT_192_BIT_KEY = b"\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xcek|\xd4-ok\t\xdb"
OCT_256_BIT_KEY = b"\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xcek|\xd4-ok\t\xdb\xc8\xb1\x00\xf0\x8f\x9c,\xcf"
OCT_384_BIT_KEY = b"\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xcek|\xd4-ok\t\xdb\xc8\xb1\x00\xf0\x8f\x9c,\xcf\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xce"
OCT_512_BIT_KEY = b"\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xcek|\xd4-ok\t\xdb\xc8\xb1\x00\xf0\x8f\x9c,\xcf\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xcek|\xd4-ok\t\xdb\xc8\xb1\x00\xf0\x8f\x9c,\xcf"


class TestGetUnverifiedHeader(object):

    def test_valid_header_and_auth_tag(self):
        expected_header = {u"alg": u"RSA1_5", u"enc": u"A128CBC-HS256"}
        jwe_str = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." \
                  "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7" \
                  "Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgN" \
                  "Z__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRir" \
                  "b6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8" \
                  "OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0m" \
                  "cKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A" \
                  "." \
                  "AxY8DCtDaGlsbGljb3RoZQ." \
                  "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." \
                  "9hH0vgRfYgPnAHOd8stkvw"
        actual_header = jwe.get_unverified_header(jwe_str)
        assert expected_header == actual_header

    def test_invalid_jwe_string_raises_jwe_parse_error(self):
        with pytest.raises(JWEParseError):
            jwe.get_unverified_header("invalid jwe string")

    def test_non_json_header_section_raises_jwe_parse_error(self):
        jwe_str = "not json." \
                  "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7" \
                  "Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgN" \
                  "Z__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRir" \
                  "b6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8" \
                  "OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0m" \
                  "cKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A" \
                  "." \
                  "AxY8DCtDaGlsbGljb3RoZQ." \
                  "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." \
                  "9hH0vgRfYgPnAHOd8stkvw"

        with pytest.raises(JWEParseError):
            jwe.get_unverified_header(jwe_str)

    def test_wrong_auth_tag_is_ignored(self):
        expected_header = {u"alg": u"RSA1_5", u"enc": u"A128CBC-HS256"}
        jwe_str = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." \
                  "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7" \
                  "Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgN" \
                  "Z__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRir" \
                  "b6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8" \
                  "OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0m" \
                  "cKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A" \
                  "." \
                  "AxY8DCtDaGlsbGljb3RoZQ." \
                  "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." \
                  "invalid"
        actual_header = jwe.get_unverified_header(jwe_str)
        assert expected_header == actual_header


@pytest.mark.skipif(AESKey is None, reason="Test requires AES Backend")
@pytest.mark.skipif(RSAKey is RSABackendRSAKey, reason="RSA Backend does not support all modes")
class TestDecrypt(object):

    JWE_RSA_PACKAGES = (
        # pytest.param(
        #     b"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.qHxZy-MfqRjCDAieY5AoU75XRGS7S-Xx4NytHgNa5dmGh9R8q1riHyPw5Hec_D395fKqV75u1hKke5r-jgiDTaCicQjOuxM2cSaiFlUid7dk5zIucaKH84N8jMzq3PwBePmGftePM2NMCzs6RvWBFP5SnDHh95NU2Xd-rIUICA7zIBXTwNRsB2LM9c_TZv1qh59DYoiSHWy94WXJBNFqViuVLmjVz5250J6Q4uRiYKGJKEGkfLDUp18N97aw5RQ35jJF6QyO5JkeLFTA0L10QAEtM8RjBRrKYgJ6fJLCVbHHTf7EKdn6Z-4cIZKtYe2d7PPKa0ZWZvtYTuU1S6DgmA.gdSr6lSIci4GjzMsdLaK6g.4ynh6gGG4dzxpmNfZHo6o8Eqp1eXRhKzI2Tmde-IulU.cFUhLtodRUqZ1GfSO6e3pw",
        #     id="alg: RSA1_5, enc: A128CBC-HS256"
        # ),
        # pytest.param(
        #     b"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.Ju8YCub_jjFt4WR_pOIyeiXLtfwhUl-FMNETu3PMRVV8v6pD2-X4AFNWeA2pAX1_DkUIJEP8J3mjFdZB_ah6wb1ab0je-aSk3d8di8ES93gv_DkwWHkz_cjbm2At3JEh2gO252O3Ychjn8C0gMnLiXJN9Qmg_nF1drpvSdhgFz0FEI-2NlhD-0d8yy0ROMaMEby7aX7ouXP6QI3PKiwFYgPB-dtMzvF2cmZl_g3sLde9l1-U2e8JIpAW8vqQCO8Jswr0B6nH_LjUIBUEWS5vipqTa_v9siaAgLI46T5kEMJhnRVjJHvIkfnFABn5fCCVtgx2VpVrNkcejqvfLjIyNg.qyfq0GH9NgQOjuyEIKRQdA.FUb4QogxGaOslBqaTlcYqGGmhMXS8uTXNY0mpV7VPkQ.gi1jZcKEJoBey_5YBxSFVDnZulAlRPkq",
        #     id="alg: RSA1_5, enc: A192CBC-HS384"
        # ),
        # pytest.param(
        #     b"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.2r5K6UQ4a8PDar1lpsLBNnMSwPuffn3vVnI-fbFCBKTzRUSgzWiMYKd9PCBFQIA5D3E8bwQiMY0tgiHNuCZF4PaLJp99SVKkbwp0H5681mFgpQ5c-QtPHMa5fA7_zOt1DRN67XddKTSKLm7_3RQ2twU4rg3DVS-aElZZSV74Rip_KKeoDvaoJBfPY4HPFqiR96dHLdLCoSzks1XzmRxo36cY2wb-4ztWUd2J5-_7ps1khUvffOMFJuox2zk9FYIqHXZQr9eL3n4cdF-M-tFvfjBenUThW97byckr1gyWzHCUOcaVHAP3jp1xubPahtkCpsOGAvqwiO9ahRtY0afhyw.xTKBz19OoA1Av0OfNVPgOg.FCNLcCHaOGBjQSLw8vJ_2K5ROdsm0m8YkKdkSGGzX98.M5fPe-ZDlF9xjS6YELgFS30sllUK_5FZ0vBqmmKCWpY",
        #     id="alg: RSA1_5, enc: A256CBC-HS512"
        # ),
        # pytest.param(
        #     b"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.QYbUBjDR7tf1NsbLOsVg3oub--eOgcm-a9BWJ3VIlwUWlE6ybdNFY-tgib69bFeDVJUgFipGbjpx99xbsn12F4dIZvDy0S9XWqKZ4GHXCtcButxyxyusQl-Qw0Myfd9OFEDmCnjCcU_Z2UamlsSK5c9OQa9F832bwlsOvufvexAUIoqNI94J6MCzWYn03zNcuKXd2EzbTXWRcxUL5RMQ_fFJb5mVEoRArw5H0Q9vCsjUkBGfvrLNr810yZrOIZLKrUW5Gq7vK2RR8GrPX1R1NIIrWe7FJgp1qr18-74q2vkNA8oGQitH1s0UJXXYObrJYZUZMGDh5NkGHyct1MwAqg.6GmP0pU4BfLq9vft.Lr_B5NID1Jsz1E-N9Hxz4PM7XV99sg.vNGa4jT1-N3eb7MZoj7REA",
        #     id="alg: RSA1_5, enc: A128GCM"
        # ),
        # pytest.param(
        #     b"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTkyR0NNIn0.MzQZeR7Arzqg1vqA83THaJ-EhKfIIA3U6ePDbUneSeJz0p_9WVmg7IyrxOax2vTTLrx3RLZKXtXzVw8B3dMiXYJtZYTV3mw33m3tehlXu_w0dnWJycFBb5tf-ScesD-u7RdIBqbuMF9SR8EKDrgXg0gL_UkW-Jitg06QdH3lcGlQRl2cwGuNFFrFDBFR5OkoSd0ww1LNJmHzsTwnRouQfGfOTM2wj-D3rnqTflS6088XhvPUyqt5ASJy6sPLSfAuA_gIUXpgQDQUSaAI2C4ANN_Y56YJ83EACkFDwHhdhEm3etP0GhW8G4-iRURxgad49KZWlV6jD08hb3Y1w8CjCg.1NL2zXlApxrwDlm7.1b0_SmBkvJSDr-m5awRAc6CHhc1lPw.qHTNRK-bFsjvG6V5qpBbvw",
        #     id="alg: RSA1_5, enc: A19GCM"
        # ),
        # pytest.param(
        #     b"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2R0NNIn0.FmKpIISKPpeA45DVJFzuHuZzuDBc9OblwI1pa80rwlKVB7GhhTpd4aXYWRLU4qMNUfGj_Imlxc0rYdOfPa1IvCrrED9KjR5H604ruZgJZigoYCkS3WnAUnMCIOaDSP_Ye2UC4OTwnDSXRIdgnoyM-g9l3fOjgSeoc2aCSRE5DGHrgEpvzaFWDl4YDD_im7IsFEM8H7H2TAlN7ftkbKN6jd9MMRDXd6y7HYvNm4Hi_gPDM70TWhj-LIb6NmJE19EAboy8Ul8HAFdaCAFxwlLa6tFQyOuw-PLnZQ_soLGZXUeFNuYOafIjmPL2tgJiHfj1K_IPZwmWZS2d4I45He3CRA.xAUHSwvfz51m45eo.XeSm9hkA2mUNPk9eiaZx-I7mY4ZJqg.T0S3B4H4KusBzyZos81EIQ",
        #     id="alg: RSA1_5, enc: A256GCM"
        # ),
        pytest.param(
            b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ.wQh8pyyAMCQRMAeMMIXStaoBCytZ4Upd7hFqpGxkoHq6aCDjjXywERJqgx68co_vz29JkTlK0Z2UsUOLjM4M6TeEiKgw0zT7ENXehP6VeE0bo2_cCx0k8A_af2eJXpsaqIvRsdkqYCsSW96H_eq3PoqOx96DNWTHxY5OTDjthr8B5WCYx3qA1oepT1HXSfCDB_01Qg-OREMu6l4Qc3i-ci6kQfhoAHb-sowpM8tUPvOx28z9-3a5_HxWMh0jFez86d9RHCecJx1UxHMJ6GSCzd2ra2xKi1gqaiC8MZupjvVJeGEpb4uriFmw5zJ9YGnefLj9NPMvj79XTrjD4AalaA.o9RgfKTIB5wbkrRr-wkO0Q.7ejS9gM307dU3to_V3AtqukA14IhuFyLrRG9RmRH2cw.hXUMRYby8afLVMI3H-WHYw",
            id="alg: RSA-OAEP, enc: A128CBC-HS256"
        ),
        pytest.param(
            b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExOTJDQkMtSFMzODQifQ.u3QeBm1xbLlQSoDZJ5QFLT5KnTBvxHuh5WCb4Yt-jRVipJ_7DWBORoAsFXV-SB3oIeRlchcPX0QK2bz_uxFxNZGF9aLgROZXmyFGUs-S_6mewqnxiCgWcgM1fOvast6d65_Zrp8kgz8oev4EiuXwb2X1OO31BEOn3aZR7QGdD6O59q6pF79OU328hpKatqBjW4IdIgg68rtA2-87Xj9VqpqUBkgzJCf-z038yQR41GNVTRzMk6N2M3MgRYUFkqUHy59TRwplWQuRZ9vmkdotRGYI0ZQ7V5PzXhqYSJnx5Y9jYlIqv7sdz_b6lyqxkrtJGBRNfAFiil4HABIobx5YDw.2oKvl74hWoa3zpABph4L9Q.04KyNsCkVQAX-s547eYJOfj6SBR3cZypu2qy7ua4DUg.AKJwqOIH7wK3_7n_DmvZ96yq1vm3d6Mh",
            id="alg: RSA-OAEP, enc: A192CBC-HS384"
        ),
        pytest.param(
            b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ.Kbd5rSN1afyre2DbkXOmGKkCNZ09TfAwNpDn1Ic7_HJNS42VDx584ReiEzpyIoWek8l87h1oZL0OC0f1ceEuuTR-_rZzKNqq6t44EvXvRusSHg_mTm8qYwyJIkJsD_Zgh0HUza20X6Ypu4ZheTzw70krFYhFnBKNXzhdrf4Bbz8e7IEeR7Po2VqOzx6JPNFsJ1tRSb9r4w60-1qq0MSdl2VItvHVY4fg-bts2k2sJ_Ub8VtRLY1MzPc1rFcI10x_AD52ntW-8T_BvY8R7Ci0cLfEycGlOM-pJOtJVY4bQisx-PvLgPoKlfTMX251m_np9ImSov9edy57-jy427l28g.w5rYu_XKzUCwTScFQ3fGOA.6zntLreCPN2Eo6aLmuqYrkyF2hOBXzNlArOOJ0iZ9TA.xiF5HLIBmIE8FCog-CZwXpIUjP6XgpncwXjw--dM57I",
            id="alg: RSA-OAEP, enc: A256CBC-HS512"
        ),
        # pytest.param(
        #     b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.SUDoqix7_PhGaNeCxYEgmvZt-Bhj-EoPfnTbJpxgvdUSVk6cn2XjAJxiVHTaeM8_DPmxxeKqt-JEVljc7lUmHQpAW1Cule7ySw498OgG6q4ddpBZEPXqAHpqlfATrhGpEq0WPRZJwvbyKUd08rND1r4SePZg8sag6cvbiPbMHIzQSjGPkDwWt1P5ue7n1ySmxqGenjPlzl4g_n5wwPGG5e3RGmoiVQh2Stybp9j2fiLNzHKcO5_9BJxMR4DEB0DE3NGhszXFQneP009j4wxm5kKzuja0ks9tEdNAJ3NLWnQhU-w0_xeePj8SGxJXuGIQT0ox9yQlD-HnmlEqMWYplg.5XuF3e3g7ck1RRy8.VSph3xlmrPI3z6jcLdh862GaDq6_-g.3WcUUUcy1NZ-aFYU8u9KHA",
        #     id="alg: RSA-OAEP, enc: A128GCM"
        # ),
        # pytest.param(
        #     b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExOTJHQ00ifQ.kdii1x_TeLMSEEyLL1YneYlAs24kExW6t7f4pP3NbAPNO2YU9YTOHBoWfE8_KzW2kFG-dCJSMTgeRrpHCweHeODRk45cwG9ljMv3FdoRCk_chT0qoAYFOiWgZu8mPZfPTasQWjKQtEXTfrxRzHLFJt14d5yBvzcw8eQJ3T3853HNU_iW0rxxPJEsvojJj80mRzRrInSNA79MLkKmJvcM6C0EDq55AEj8tCZI-B_0UuEUzwziFqyJU7Hj9r9EIAHCK-YJPRmzLi6Qz3H9-MDnnpGyQDsqNpQerRFcXXcE4vtVG5c7r91rbzfucYA4gMR8x1Tl2doZtUdxTVrk0F7UJg.nIb8f24bjnhXLPxi.mQadCeZvt7mwyrgA5pyIxZwz7gkvdQ.rYwma97CLBfXABTSbL7DGA",
        #     id="alg: RSA-OAEP, enc: A19GCM"
        # ),
        # pytest.param(
        #     b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.kINITl6EJC8SY4Y8jejN1lnuwUeENgXUmYMS_wb2rcMga63pDieYdbm-ENlsFnFIC8ANukR_lx5TIhULJAVtPHFqN2Yyb8sOuG6JKX76E6DuBj1RdS6ejpVMBNNsiNYXYxvjsVnHMyBCE48zur9sZGFaHa3Sw-_Nnesm0ygo96AuTTnz6L-mzdpPK-EhWsA1fGaR0g0EpGyEjMh6NGp6n4BRqIbeSSOOwVW39akcnSs5Wl3gZq0tN0kArq_0dN4i-Yuqm30F65MQrTn7-nnjQCoXGkzlPlU9Ex-jWtkbqqjrHqJy-Gp_AVY24PRL7a_N5AHr1WHrcrkLdZEHmjGRMA.g0_LDNNkHJ7hUjGe.WwVpEFWAZ0GXhk2YhysMS9UMBs-yfQ.fTSHPmG68YG7VHIy0-r8vQ",
        #     id="alg: RSA-OAEP, enc: A256GCM"
        # ),
        pytest.param(
            b"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.K6cguIsijzwwak3cqBzKlTb3izuWdFDrvClKDscxuPCfSy_dEH-WMalroPtf8sLdEa1ocrZF7udDQk6_uhD3BGy4pytFvkIy8H9jw2o7bYGU7M2qvm7CKrAE2rxk-CU4CRZItF9PWIdKxKSdvMd2lojVgLuiQKPu0EvZFW4OeV4X77Fy-0b9PcGkbkJ9iehKHk9yjqGJAGMiyTOse7_-cyXgLMJgiSKQWPfAgHYGPN39PbH_cPjxGsl4WwawmUxnEmcQ2ctVrtfvbieupGpL9LkHXIf3I08LXh8hbYGKksWeZOBDhmtKWoAnP7PrjRNeAHIag4NqTlnA8ZXx7dtS2g.uU6nyQdGTAvfbNijkodnfQ.02Bukf1CnQWB_jYUDFSooXGzqDXW0QyKvIzE-slzQtw.Tu7u7yN8HPlS7oHmmc-OQQ",
            id="alg: RSA-OAEP-256, enc: A128CBC-HS256"
        ),
        pytest.param(
            b"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.AKPATE5ww9Lcpbmo7OSA3ulVO4Y17mni5sYyLoc4Lvj6Wn9bHuzhFLyPA16qDDJsNE5pXxC5wemuAQugXQReeU_nSPsFYE_D7tUR4jMCrFZHMUshq0Cml7bgc34vXtBuxSMAHu16JjFI52mZKTHjFcBqCxDHE8EKWf7EdaPZf06swWKeZAnOAaRh2i9wVMzmpCJ9cFCYv0T31FTkr2XG1ydgZP2TAnMevRuTvtZ6e5xsc6lq0IH4nQCqKp6Hnb8aaoiKKbQMHNWAcmJzWYBpM2Sesv6zvzkacASMjwvx301dQKFVWV5x8Ocx2klcPFNdIgevWyT0-mLbbxgVAWFiaw.aoWEVUUMXkE7jbBBlG6UTg.fQmbAROAo1D6DHczAX3MH_eJfvRVHveJt6po1_jRud0.JSuCoAEXq4JUbZYYlGSqXd70QSr8V0U3",
            id="alg: RSA-OAEP-256, enc: A192CBC-HS384"
        ),
        pytest.param(
            b"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.nYIo9bUQgrQlnANR1IQI7EKPU75R2AoJR_44xXr5fEjEf444ucNbQvarO6HN5R_LQMEb0If7b8VyViMku1LuuFhYAoIfToT6SCcUgWG4vhN8mdc2Y4YsGqyF4k1c_EbQ3Gka_O04VZyhqukwpKUr89ASzqyJCWoP3kdiVfdjIkFnA_ApKGhnn2AwCy9_y8gW5TIVddYcOrQNVJtmxUWTgw6AxJSJkQztNfny6rbWdygXdeBXq7T4uAZYDquniE_h8f46SEUBb9UuMCq4eKVJZYJfPrKBVBMY9vncm-HAhl_IHzegLSJMgBWq_-idGMooxAypDg_Zi51zCpxinyrKeg.BiZjLouM-sJOpTprqKNVWw.0zL9BEdBAglQ-DQ2pBjJrRFsUt7qugRp3_nOY-sr75c.mcUVI1GvddAtqDMzElYzshrtS1GgnrUCb5brd2qzBlM",
            id="alg: RSA-OAEP-256, enc: A256CBC-HS512"
        ),
        # pytest.param(
        #     b"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIn0.I8HnspRs9CiFyDyumZm5YthOVLl8Vn1unThm_EQd5YGcn0WPqXtrKeAWoP4rfOn7XaRNYeuLowpHEl-CzCjoEPEW-vui-t-P1JbDH6_wGwbdVIppdcwS6Npyv5qCNI21gPBDUB2twytEGqaYGKbbexxS8iE9iU4C_Wp-42axvUKEpxxNlQn-gPmHt4ZuzMGbI9Rl5wzT583SgmHwqXTklVC02aWQY2xQYelq5IVK-UBQ8J_NOBy7SeNeuAtmh7YxLGucSVlTqmzHImkOxsDU2UEiGJK-u8eGrgawx7DFSTUx8KXeMpsF2qe87PZhkSthpaqLFj1ZFQmVycnsN28IFg.C2qD0Dpiu2xWiDKj.o5WfgRbXOMzosaKtFCKpRyZ3nHJqLA.l8iOYFrtzGgd_x8ToB5d7w",
        #     id="alg: RSA-OAEP-256, enc: A128GCM"
        # ),
        # pytest.param(
        #     b"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTkyR0NNIn0.vog1TjNQiLLiVP5vf8OxnQjkvi9QmQPBQWAd_m9eUBSn_lsfhBTdButrKeGhEiT-scDiy1iokmgnMAozwL7L7iUB1opTBJjk0Dy_eYNKgePz6aGrtecegcWWb2c9Jyb1ii0LVrHXibOk6tA_N91phaqaxzyWfHrNDgmVb7MCZ5lXrqJe57f6djtF7M9bAKFHkRtBv5agPFrZ1NXaufovfs48lk5LVFR1NwucgT9eAXRuH90jV1Mz51NHZDlrD2-4Pv-x3sOCQxm20635QjH9sc1E6SyQEyNkQig7UrAGO6Z4KyKt5uy0uKZiOmVwcSE9-iniad1a2VmMWUyzYMJSYg.AOFzpp3CX-hQdox1.NHzH7vSRCcYMRr3tlTkpvTlmfCi17g.bUig4bKO12k37eW6a4DGHg",
        #     id="alg: RSA-OAEP-256, enc: A19GCM"
        # ),
        # pytest.param(
        #     b"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.t4GUc1VzGpvHffTimMbZ15T7aetoyGdtudtrLaQC_Mxfmo6IPa42VhrQDejxEeFBUOXHKJEDUbSorZkx8KwPdjvXGSBYljYUYDT3l4FXtCnSeOFZ43vdkZRdhbzZF49Pz2WMtsEKefjefnVDVCZi8R6kFDpKeQQtjZIN-rxRPHVuqar6MhV8KK90ywQKE9l6TQazEZIdPQqRfnYBhpJk2Jfpc4tSMH4n6TW-7mGWpBVuYKJlzfSObbMN2byugZwFBq9QmrOCfAgIW-94XEMwl-EIWv86otrRzKuWiJknd6dhW4-s_4ru-QBJE3bdzSe8lXtWvxW7HqBlkKw4qEv1Rw.eedGFQdC_X08OY1t.bxnIPwrPDdyZCu83IMdUDAc3ILKfFA.lGXMXWt22gI25PtO1FBKfQ",
        #     id="alg: RSA-OAEP-256, enc: A256GCM"
        # )
    )

    JWE_128_BIT_OCT_PACKAGES = (
        pytest.param(
            b"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.FWUgqCHDyNE1h3JDdr0Xcu5L5bBmpdeD9ARY7nWI6WqwgTkd9jSWyQ.pipi1JvdyC5xhUpeSv062A.JGWrXZDi8k0kWvFjRFIqm4PPgEXhY1XTrI9ck5UwsLs.ADFsMOoG9hCfWKBCfwb2mg",
            id="alg: A128KW, enc: A128CBC-HS256"
        ),
        pytest.param(
            b"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.6Q2A5mNASmztSzClkWP1wnd4xJeqwWLXSjZeX4Hsrv88lHfmvztzJW922w_bTbrR6IXf8sIy4Uk.j3mIgJzZiT_VQBTALj-7uA.Rg4WCyrX92hmHcFCrnb4pW1p0kPL7vwr_2vCXf14JqY.XJ7R2DJ4TsrP5aEO7YUb8PIp-biZd-Er",
            id="alg: A128KW, enc: A192CBC-HS384"
        ),
        pytest.param(
            b"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.Ip3Mi-KOCGlMpJtzrjXlkiV_2bIrZyfzPGQxqCqJz7002cln2Zl2-HFxO6AOpTZjMPnAEwYB3jbsVzes1dMRaAsz8Y7j6U6b.W5SPAPmqYDk4EhzbesYsdg.ghwIBO7RLfDwuwBdNIu1CSY7TofQqk9Qfoh-mj047HA.j1ClyE98XpccpSIhgSKcjX-EqmcTMck1kSMhEffWpvU",
            id="alg: A128KW, enc: A256CBC-HS512"
        ),
        pytest.param(
            b"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0.p-Ql3KS3eLpCYayduLAJRFnlrDxmz-Xq.MtcOoO69-uLGt0ky.oxFJvn7ukxDxOrRF5mAw48LT0zEK8A.CwNht_Y8MJVreFHiK_-8Aw",
            id="alg: A128KW, enc: A128GCM"
        ),
        pytest.param(
            b"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTkyR0NNIn0.ymZfpi2OXzZNDGQIRYIYZpEKSp9v0_IAuLs4WFcJh0w.PiPrjIBhijp-jRzJ.71t41FWCt8CevMb1STEAZgbyRJYRmg.cG3mcRX9GMyWDK9wy8C-5w",
            id="alg: A128KW, enc: A192GCM"
        ),
        pytest.param(
            b"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIn0.w3-MmOm9vYWdeivDaTg4VBaup2cJLK-FuDw-CtI0EzK710-5nehU0Q.itfVwUGOSA8uUy1l.4BUA8kHkLlGVQewn834kiWmh2dwFvA.uhPEhYVsKtrA86gVmA58fg",
            id="alg: A128KW, enc: A256GCM"
        ),
    )

    JWE_192_BIT_OCT_PACKAGES = (
        pytest.param(
            b"eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.VI6KHzm-7kZ9lzZVcPaGxGfcP653rRS0TeO-mx9tf8edfktAwVraCg.QClSFzlqjEj8wuVSa6d4vw.BO-5uYmzkB4KG-BrJJipuZ6tBKLiYcPzRtezvwoPiPQ.FYpFwhxI0frlN2mPL9Q4yw",
            id="alg: A192KW, enc: A128CBC-HS256"
        ),
        pytest.param(
            b"eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.zy-FQk4HBV8H4eOfPjLJNQCL25QxRlKqRN_oog4hkcKbNe4m-n00GkoJrPhbA2_zUaSmmA03Cd4.hpMhDE2TLyNJuYKapas58w.PRzPBH4nCFPXH7ZPxdduiRUS11L5KuTIGTEDiJF2UnM.myYzLhoj_EsmKprZCCNW1EnjZx0L5p6X",
            id="alg: A192KW, enc: A192CBC-HS384"
        ),
        pytest.param(
            b"eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.sLZTEz1ekFy7Zc1GUR1Ov2haIc0B8IeOTv9nWWfzfG60yRVHGylCTg.JB9Qf8YbJbq7UneQQNvRHQ.Qe_DIeW3TfNPH-cZ63vE7Fg3rs_ducWB4jUDso3nL00.gMJK5_yzy2kMWpjhCeCxYw",
            id="alg: A192KW, enc: A256CBC-HS512"
        ),
        pytest.param(
            b"eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTI4R0NNIn0.GFHC6pWUrMPS2Ne0LoD262ZRdDsuIHlm.5t-ctv43XznqPW3q.H86gDQWHbAFx0vQg5GnMmByzE62sXw.LsW7RR6rSuBLNQUKjXo3eQ",
            id="alg: A192KW, enc: A128GCM"
        ),
        pytest.param(
            b"eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTkyR0NNIn0.jCqGA0d0ZlJMh5zAC61xleR6GJVqkJdHd6Z_KYnOQCY.aBbG_wxdGR2v9xy-.iItzJTbtPO36_NkYryISCUg2yZLPqg.Czp7vQjkYY52L_-5e5Mftg",
            id="alg: A192KW, enc: A192GCM"
        ),
        pytest.param(
            b"eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMjU2R0NNIn0.EIaUBHuqEgGsAofE0RIux_Z74KywMHwgJsWqzIh1d6y-ZlajLeFxZA.KucKNVKD7LkxK55G.SErdT9bgvEUd7BM24U7U2DY_iEpVsQ.LmnV18_JHi8b-K6-L3cMnQ",
            id="alg: A192KW, enc: A256GCM"
        ),
    )

    JWE_256_BIT_OCT_PACKAGES = (
        pytest.param(
            b"eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.eIyuHsu7hwSgBE9hEiCRFdDJNR8NxGLMZG_fXOAEwwxtKSS2aajNQw.0d0fDHcsSzNuKly5INWDsQ.biSkEEKmvCK6IXOhkOlardXzz_N_1bKQr3ej_YOq-Q0.lSvOacktoBx5bnJjTDPgkA",
            id="alg: A256KW, enc: A128CBC-HS256"
        ),
        pytest.param(
            b"eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.5n8sAMauHzLxaPvIcr785iQqxXs_-VhPWIvB_wwmHr8oIvWFAA4Bxr8yozJlignLYFp9hhTtqFg.WRsNeFZmHrWxxmHT0ERg9g.F3J8btCBslrfQWURF2yH0ylII1rF3JR2HrN1kGvz2x8.Hn8E8mgnjpFhFWQQAk_VpbT8kROw8Q1e",
            id="alg: A256KW, enc: A192CBC-HS384"
        ),
        pytest.param(
            b"eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.YbyodZkdjUg7rs-Un5AzgUqZuPo8brRD5Adgcz0IllKzv5C_Bo1XVHFQ2Yn7Scz-EapFNk_VTW_qfYeu6nAn6FaCQw56SOIR.T9F36c75q-R7FhX-SsLvWw.BK4HANOyq0jWRPdyr6qEcAdBGzPAfNkuQQmCV-w4iEI.YLzkW9d9fhaQbM2vw5m_GGHAbMQ3BZu7mX4lIUutf_4",
            id="alg: A256KW, enc: A256CBC-HS512"
        ),
        pytest.param(
            b"eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMTI4R0NNIn0.xswSGb-SCfbE6DjY0WCB1shloUPOBv2m._S5f-La7_N8FdZB6.cBQGJpjcs996pYnVtTpaLByJuH8LaA.uChcpwk-lyLfMMVBBy-iyg",
            id="alg: A256KW, enc: A128GCM"
        ),
        pytest.param(
            b"eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMTkyR0NNIn0.V0Nou9Zky4yo_9ghGF8hlxLfqzrLh8eplUDb6ZOqf48.xzy6RIznrhm4jKEn.gnGscbtj1t5YgvNLV5wzM49l6I0BuQ.xzFTdXEFrNT4ZCbeqiF5FA",
            id="alg: A256KW, enc: A192GCM"
        ),
        pytest.param(
            b"eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0.s_kDN1X3i_JyNEd6UrQOol1OmBn6StkDgDCL4eUDENgrZADS34M_3g.DRjr32KpZgwvqwe5.0PoZ7b5H7fcSysmawuvVaxVqCcaOFw.P264dHQzuRHI_mu0A3yVAQ",
            id="alg: A256KW, enc: A256GCM"
        ),
    )

    @pytest.mark.parametrize("jwe_package", JWE_RSA_PACKAGES)
    def test_decrypt_rsa_key_wrap(self, jwe_package):
        key = PRIVATE_KEY_PEM
        actual = jwe.decrypt(jwe_package, key)
        assert actual == b"Live long and prosper."

    # @pytest.mark.parametrize("jwe_package", JWE_128_BIT_OCT_PACKAGES)
    # def test_decrypt_oct_128_key_wrap(self, jwe_package):
    #     key = OCT_128_BIT_KEY
    #     actual = jwe.decrypt(jwe_package, key)
    #     assert actual == b"Live long and prosper."
    #
    # @pytest.mark.parametrize("jwe_package", JWE_192_BIT_OCT_PACKAGES)
    # def test_decrypt_oct_192_key_wrap(self, jwe_package):
    #     key = OCT_192_BIT_KEY
    #     actual = jwe.decrypt(jwe_package, key)
    #     assert actual == b"Live long and prosper."
    #
    # @pytest.mark.parametrize("jwe_package", JWE_256_BIT_OCT_PACKAGES)
    # def test_decrypt_oct_256_key_wrap(self, jwe_package):
    #     key = OCT_256_BIT_KEY
    #     actual = jwe.decrypt(jwe_package, key)
    #     assert actual == b"Live long and prosper."

    def test_invalid_jwe_is_parse_error(self):
        with pytest.raises(JWEParseError):
            jwe.decrypt("invalid", "key")

    def test_non_json_header_is_parse_error(self):
        jwe_str = "ciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." \
                  "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7" \
                  "Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgN" \
                  "Z__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRir" \
                  "b6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8" \
                  "OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0m" \
                  "cKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A" \
                  "." \
                  "AxY8DCtDaGlsbGljb3RoZQ." \
                  "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." \
                  "9hH0vgRfYgPnAHOd8stkvw"
        with pytest.raises(JWEParseError):
            jwe.decrypt(jwe_str, "key")


class TestEncrypt(object):

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_rfc7516_appendix_b_direct(self, monkeypatch):
        algorithm = ALGORITHMS.DIR
        encryption = ALGORITHMS.A128CBC_HS256
        key = bytes(bytearray(
            [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170,
             106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240,
             143, 156, 44, 207]
        ))
        plain_text = b"Live long and prosper."
        expected_iv = bytes(bytearray([3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111,
                                       116, 104, 101]))

        for backend in backends:
            monkeypatch.setattr(backend, "get_random_bytes", lambda x: expected_iv if x == 16 else key)

        expected = b"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.BIiCkt8mWOVyJOqDMwNqaQ"
        actual = jwe.encrypt(plain_text, key, encryption, algorithm)

        assert actual == expected

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    @pytest.mark.parametrize("alg", filter(lambda x: x in ALGORITHMS.SUPPORTED, ALGORITHMS.RSA_KW))
    @pytest.mark.parametrize("enc", filter(lambda x: x in ALGORITHMS.SUPPORTED, ALGORITHMS.AES_ENC))
    @pytest.mark.parametrize("zip", ZIPS.SUPPORTED)
    def test_encrypt_decrypt_rsa(self, alg, enc, zip):
        expected = b"Live long and prosper."
        jwe_value = jwe.encrypt(expected[:], PUBLIC_KEY_PEM, enc, alg, zip)
        actual = jwe.decrypt(jwe_value, PRIVATE_KEY_PEM)
        assert actual == expected

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    @pytest.mark.parametrize("enc", filter(lambda x: x in ALGORITHMS.SUPPORTED, ALGORITHMS.AES_ENC))
    @pytest.mark.parametrize("zip", ZIPS.SUPPORTED)
    def test_encrypt_decrypt_dir(self, enc, zip):
        if enc == ALGORITHMS.A128CBC_HS256:
            key = OCT_256_BIT_KEY
        elif enc == ALGORITHMS.A192CBC_HS384:
            key = OCT_384_BIT_KEY
        elif enc == ALGORITHMS.A256CBC_HS512:
            key = OCT_512_BIT_KEY
        else:
            pytest.fail("I don't know how to handle enc {}".format(enc))
        expected = b"Live long and prosper."
        jwe_value = jwe.encrypt(expected[:], key, enc, ALGORITHMS.DIR, zip)
        actual = jwe.decrypt(jwe_value, key)
        assert actual == expected

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_alg_enc_headers(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg)
        header = json.loads(six.ensure_str(base64url_decode(encrypted.split(b".")[0])))
        assert header["enc"] == enc
        assert header["alg"] == alg

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_cty_header_present_when_provided(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg, cty="expected")
        header = json.loads(six.ensure_str(base64url_decode(encrypted.split(b".")[0])))
        assert header["cty"] == "expected"

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_cty_header_not_present_when_not_provided(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg)
        header = json.loads(six.ensure_str(base64url_decode(encrypted.split(b".")[0])))
        assert "cty" not in header

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_zip_header_present_when_provided(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt(b"Text", PUBLIC_KEY_PEM, enc, alg, zip=ZIPS.DEF)
        header = json.loads(six.ensure_str(base64url_decode(encrypted.split(b".")[0])))
        assert header["zip"] == ZIPS.DEF

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_zip_header_not_present_when_not_provided(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt(b"Text", PUBLIC_KEY_PEM, enc, alg)
        header = json.loads(six.ensure_str(base64url_decode(encrypted.split(b".")[0])))
        assert "zip" not in header

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_zip_header_not_present_when_none(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg, zip=ZIPS.NONE)
        header = json.loads(six.ensure_str(base64url_decode(encrypted.split(b".")[0])))
        assert "zip" not in header

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_kid_header_present_when_provided(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg, kid="expected")
        header = json.loads(six.ensure_str(base64url_decode(encrypted.split(b".")[0])))
        assert header["kid"] == "expected"

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_kid_header_not_present_when_not_provided(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg)
        header = json.loads(six.ensure_str(base64url_decode(encrypted.split(b".")[0])))
        assert "kid" not in header
