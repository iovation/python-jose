import pytest

from jose import jwe
from jose.exceptions import JWEParseError


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


class TestDecrypt(object):

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
