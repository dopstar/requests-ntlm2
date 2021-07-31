import base64
import struct

import faker
import mock
import ntlm_auth.gss_channel_bindings
import trustme
from requests.packages.urllib3.response import HTTPResponse

import requests_ntlm2.core


class TestNtlmCompatibility(object):
    def test_ntlm_compatibility_levels(self):
        assert requests_ntlm2.core.NtlmCompatibility.LM_AND_NTLMv1 == 0
        assert requests_ntlm2.core.NtlmCompatibility.LM_AND_NTLMv1_WITH_ESS == 1
        assert requests_ntlm2.core.NtlmCompatibility.NTLMv1_WITH_ESS == 2
        assert requests_ntlm2.core.NtlmCompatibility.NTLMv2_DEFAULT == 3
        assert requests_ntlm2.core.NtlmCompatibility.NTLMv2_LEVEL4 == 4
        assert requests_ntlm2.core.NtlmCompatibility.NTLMv2_LEVEL5 == 5


class TestCoreFunctions(object):
    @mock.patch("requests_ntlm2.core.get_server_cert")
    def test_get_cbt_data__no_peer_cert(self, mock_get_server_cert):
        mock_get_server_cert.return_value = None
        response = HTTPResponse()
        cbt_data = requests_ntlm2.core.get_cbt_data(response)
        mock_get_server_cert.assert_called_once_with(response)
        assert cbt_data is None

    @mock.patch("requests_ntlm2.core.get_server_cert")
    def test_get_cbt_data(self, mock_get_server_cert):
        cert_bytes = trustme.CA().cert_pem.bytes()
        mock_get_server_cert.return_value = cert_bytes
        response = HTTPResponse()
        cbt_data = requests_ntlm2.core.get_cbt_data(response)
        mock_get_server_cert.assert_called_once_with(response)
        assert isinstance(cbt_data, ntlm_auth.gss_channel_bindings.GssChannelBindingsStruct)

        key = ntlm_auth.gss_channel_bindings.GssChannelBindingsStruct.APPLICATION_DATA
        assert cbt_data.fields[key] == b"tls-server-end-point:" + cert_bytes
        assert cbt_data.get_data().startswith(
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0e\x05\x00\x00"
            b"tls-server-end-point:"
        )

    def test_get_ntlm_credentials(self):
        fake = faker.Factory.create()
        username = fake.user_name()
        password = fake.password()
        domain = fake.domain_name()
        response = requests_ntlm2.core.get_ntlm_credentials(username, password)
        assert response == (username, password, "")

        response = requests_ntlm2.core.get_ntlm_credentials(
            r"{}\{}".format(domain, username),
            password
        )
        assert response == (username, password, domain)

    def test_get_auth_type_from_header(self):
        auth_type = requests_ntlm2.core.get_auth_type_from_header("Negotiate, NTLM")
        assert auth_type == "NTLM"
        auth_type = requests_ntlm2.core.get_auth_type_from_header("Negotiate")
        assert auth_type == "Negotiate"
        auth_type = requests_ntlm2.core.get_auth_type_from_header("Basic")
        assert auth_type is None

    def test_get_server_cert(self):
        raw_response = type("RawResponse", (), {"raw": HTTPResponse()})
        response = requests_ntlm2.core.get_server_cert(raw_response)
        assert response is None

    @mock.patch("logging.Logger.warning")
    def test_get_server_cert__non_urllib3_backend(self, mock_logger_warning):
        raw_response = type("RawResponse", (), {"raw": None})
        response = requests_ntlm2.core.get_server_cert(raw_response)
        assert response is None
        mock_logger_warning.assert_called_once_with(
            "Requests is running with a non urllib3 backend, "
            "cannot retrieve server certificate for CBT"
        )

    @mock.patch("requests_ntlm2.core.get_certificate_hash_bytes")
    def test_get_server_cert__with_sock(self, mock_get_certificate_hash_bytes):
        raw = HTTPResponse()
        raw._fp = mock.MagicMock()
        raw_response = type("RawResponse", (), {"raw": raw})
        response = requests_ntlm2.core.get_server_cert(raw_response)
        assert response is not None
        mock_get_certificate_hash_bytes.assert_called_once()

    def test_fix_challenge_message(self):
        good_message = base64.b64decode(
            "TlRMTVNTUAACAAAAAAAAAAAAAAAGggkAmuCpt5hD4IIAAAAAAAAAAAAAAAAAAAAA"
        )
        fixed = requests_ntlm2.core.fix_target_info(good_message)
        assert fixed == good_message

        bad_message = base64.b64decode(
            "TlRMTVNTUAACAAAAAAAAAAAAAAAGgokAmuCpt5hD4IIAAAAAAAAAAAAAAAAAAAAA"
        )
        fixed = requests_ntlm2.core.fix_target_info(bad_message)
        assert fixed != bad_message

        very_bad_message = bad_message[::-1]
        result = requests_ntlm2.core.fix_target_info(very_bad_message)
        assert result == very_bad_message

    def test_is_challenge_message_valid(self):
        good_message = base64.b64decode(
            "TlRMTVNTUAACAAAAAAAAAAAAAAAGggkAmuCpt5hD4IIAAAAAAAAAAAAAAAAAAAAA"
        )
        assert requests_ntlm2.core.is_challenge_message_valid(good_message) is True

        bad_message = base64.b64decode(
            "TlRMTVNTUAACAAAAAAAAAAAAAAAGgokAmuCpt5hD4IIAAAAAAAAAAAAAAAAAAAAA"
        )
        assert requests_ntlm2.core.is_challenge_message_valid(bad_message) is False

    def test_is_challenge_message(self):
        good_message = base64.b64decode(
            "TlRMTVNTUAACAAAAAAAAAAAAAAAGggkAmuCpt5hD4IIAAAAAAAAAAAAAAAAAAAAA"
        )
        bad_message = base64.b64decode(
            "TlRMTVNTUAACAAAAAAAAAAAAAAAGgokAmuCpt5hD4IIAAAAAAAAAAAAAAAAAAAAA"
        )
        invalid_message = b"foobar"
        assert requests_ntlm2.core.is_challenge_message(good_message) is True
        assert requests_ntlm2.core.is_challenge_message(bad_message) is True
        assert requests_ntlm2.core.is_challenge_message(good_message[::-1]) is False
        assert requests_ntlm2.core.is_challenge_message(invalid_message) is False

    def test_fix_target_info(self):
        with mock.patch("requests_ntlm2.core.is_challenge_message") as is_challenge:
            is_challenge.return_value = False
            result = requests_ntlm2.core.fix_target_info("foobar")
            assert result == "foobar"
            is_challenge.assert_called_once_with("foobar")

        with mock.patch("requests_ntlm2.core.is_challenge_message", return_value=True):
            with mock.patch("requests_ntlm2.core.is_challenge_message_valid") as is_challenge_valid:
                is_challenge_valid.return_value = True
                result = requests_ntlm2.core.fix_target_info("foobar")
                assert result == "foobar"
                is_challenge_valid.assert_called_once_with("foobar")

        with mock.patch("requests_ntlm2.core.is_challenge_message", return_value=True):
            with mock.patch("requests_ntlm2.core.is_challenge_message_valid", return_value=False):
                result = requests_ntlm2.core.fix_target_info("foobar")
                assert result == "foobar"

        msg = b"NTLMSSP\x00foobar"
        with mock.patch("requests_ntlm2.core.is_challenge_message", return_value=True):
            with mock.patch("requests_ntlm2.core.is_challenge_message_valid", return_value=False):
                result = requests_ntlm2.core.fix_target_info(msg)
                assert result == msg

        bad_message = base64.b64decode(
            "TlRMTVNTUAACAAAAAAAAAAAAAAAGgokAmuCpt5hD4IIAAAAAAAAAAAAAAAAAAAAA"
        )
        with mock.patch("requests_ntlm2.core.is_challenge_message", return_value=True):
            with mock.patch("requests_ntlm2.core.is_challenge_message_valid", return_value=False):
                with mock.patch("struct.pack", side_effect=struct.error) as mock_pack:
                    result = requests_ntlm2.core.fix_target_info(bad_message)
                    assert result == bad_message
                    mock_pack.assert_called_once()

        good_message = base64.b64decode(
            "TlRMTVNTUAACAAAAAAAAAAAAAAAGggkAmuCpt5hD4IIAAAAAAAAAAAAAAAAAAAAA"
        )
        good_message += b"suffix"
        with mock.patch("requests_ntlm2.core.is_challenge_message", return_value=True):
            with mock.patch("requests_ntlm2.core.is_challenge_message_valid", return_value=False):
                with mock.patch("struct.unpack", return_value=(0,)) as mock_unpack:
                    result = requests_ntlm2.core.fix_target_info(good_message)
                    assert result == good_message
                    mock_unpack.assert_called_once()
