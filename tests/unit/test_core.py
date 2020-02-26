import unittest

import faker
import mock
import ntlm_auth.gss_channel_bindings
import trustme
from requests.packages.urllib3.response import HTTPResponse

import requests_ntlm2.core


class TestNtlmCompatibility(unittest.TestCase):
    def test_ntlm_compatibility_levels(self):
        self.assertEqual(requests_ntlm2.core.NtlmCompatibility.LM_AND_NTLMv1, 0)
        self.assertEqual(requests_ntlm2.core.NtlmCompatibility.LM_AND_NTLMv1_WITH_ESS, 1)
        self.assertEqual(requests_ntlm2.core.NtlmCompatibility.NTLMv1_WITH_ESS, 2)
        self.assertEqual(requests_ntlm2.core.NtlmCompatibility.NTLMv2_DEFAULT, 3)
        self.assertEqual(requests_ntlm2.core.NtlmCompatibility.NTLMv2_LEVEL4, 4)
        self.assertEqual(requests_ntlm2.core.NtlmCompatibility.NTLMv2_LEVEL5, 5)


class TestCoreFunctions(unittest.TestCase):
    @mock.patch("requests_ntlm2.core.get_server_cert")
    def test_get_cbt_data__no_peer_cert(self, mock_get_server_cert):
        mock_get_server_cert.return_value = None
        response = HTTPResponse()
        cbt_data = requests_ntlm2.core.get_cbt_data(response)
        mock_get_server_cert.assert_called_once_with(response)
        self.assertIsNone(cbt_data)

    @mock.patch("requests_ntlm2.core.get_server_cert")
    def test_get_cbt_data(self, mock_get_server_cert):
        cert_bytes = trustme.CA().cert_pem.bytes()
        mock_get_server_cert.return_value = cert_bytes
        response = HTTPResponse()
        cbt_data = requests_ntlm2.core.get_cbt_data(response)
        mock_get_server_cert.assert_called_once_with(response)
        self.assertIsInstance(cbt_data, ntlm_auth.gss_channel_bindings.GssChannelBindingsStruct)

        key = ntlm_auth.gss_channel_bindings.GssChannelBindingsStruct.APPLICATION_DATA
        self.assertEqual(cbt_data.fields[key], b"tls-server-end-point:" + cert_bytes)
        self.assertTrue(
            cbt_data.get_data().startswith(
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0e\x05\x00\x00"
                b"tls-server-end-point:"
            )
        )

    def test_get_ntlm_credentials(self):
        fake = faker.Factory.create()
        username = fake.user_name()
        password = fake.password()
        domain = fake.domain_name()
        response = requests_ntlm2.core.get_ntlm_credentials(username, password)
        self.assertEqual(response, (username, password, ""))

        response = requests_ntlm2.core.get_ntlm_credentials(
            r"{}\{}".format(domain, username),
            password
        )
        self.assertEqual(response, (username, password, domain))

    def test_get_auth_type_from_header(self):
        auth_type = requests_ntlm2.core.get_auth_type_from_header("Negotiate, NTLM")
        self.assertEqual(auth_type, "NTLM")
        auth_type = requests_ntlm2.core.get_auth_type_from_header("Negotiate")
        self.assertEqual(auth_type, "Negotiate")
        auth_type = requests_ntlm2.core.get_auth_type_from_header("Basic")
        self.assertIsNone(auth_type)

    def test_get_server_cert(self):
        raw_response = type('RawResponse', (), {'raw': HTTPResponse()})
        response = requests_ntlm2.core.get_server_cert(raw_response)
        self.assertIsNone(response)

    @mock.patch('logging.Logger.warning')
    def test_get_server_cert__non_urllib3_backend(self, mock_logger_warning):
        raw_response = type('RawResponse', (), {'raw': None})
        response = requests_ntlm2.core.get_server_cert(raw_response)
        self.assertIsNone(response)
        mock_logger_warning.assert_called_once_with(
            "Requests is running with a non urllib3 backend, "
            "cannot retrieve server certificate for CBT"
        )

    @mock.patch('requests_ntlm2.core.get_certificate_hash_bytes')
    def test_get_server_cert__with_sock(self, mock_get_certificate_hash_bytes):
        raw = HTTPResponse()
        raw._fp = mock.MagicMock()
        raw_response = type('RawResponse', (), {'raw': raw})
        response = requests_ntlm2.core.get_server_cert(raw_response)
        self.assertIsNotNone(response)
        mock_get_certificate_hash_bytes.assert_called_once()
