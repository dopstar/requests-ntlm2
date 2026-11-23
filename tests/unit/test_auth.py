from io import BytesIO, StringIO
from unittest import mock

import faker
import requests

from requests_ntlm2.auth import HttpNtlmAuth, get_auth_type_from_header
from requests_ntlm2.constants import NtlmCompatibility
from tests.test_utils import domain, password, username


class TestHttpNtlmAuth:
    test_server_url = "http://localhost:5000/"
    test_server_username = f"{domain}\\{username}"
    test_server_password = password
    auth_types = ["ntlm", "negotiate", "both"]

    def test__init(self):
        auth = HttpNtlmAuth(self.test_server_username, self.test_server_password)
        assert isinstance(auth, HttpNtlmAuth)
        assert auth.username == username
        assert auth.password == password
        assert auth.domain == domain.upper()
        assert auth.send_cbt is True
        assert auth.ntlm_compatibility == NtlmCompatibility.NTLMv2_DEFAULT

    def test_extract_username_and_password(self):
        auth = HttpNtlmAuth(self.test_server_username, self.test_server_password)
        assert auth.extract_username_and_password() == (f"{domain.upper()}\\{username}", password)  # noqa

        fake = faker.Factory.create()
        username2 = fake.user_name()
        password2 = fake.password()
        auth = HttpNtlmAuth(username2, password2)
        assert auth.extract_username_and_password() == (username2, password2)

    @mock.patch("requests_ntlm2.auth.HttpNtlmAuth.retry_using_http_ntlm_auth")
    def test_response_hook__http_200(self, mock_retry_using_http_ntlm_auth):
        auth = HttpNtlmAuth(self.test_server_username, self.test_server_password)
        response = requests.Response()
        response.status_code = 200
        new_response = auth.response_hook(response)
        mock_retry_using_http_ntlm_auth.assert_not_called()
        assert new_response is response

    @mock.patch("requests_ntlm2.auth.HttpNtlmAuth.retry_using_http_ntlm_auth")
    def test_response_hook__http_401_basic_auth_header(self, mock_retry_using_http_ntlm_auth):
        auth = HttpNtlmAuth(self.test_server_username, self.test_server_password)
        response = requests.Response()
        response.status_code = 401
        response.headers["WWW-Authenticate"] = "Basic"
        new_response = auth.response_hook(response)
        mock_retry_using_http_ntlm_auth.assert_not_called()
        assert new_response is response

    @mock.patch("requests_ntlm2.auth.HttpNtlmAuth.retry_using_http_ntlm_auth")
    def test_response_hook__http_401_ntlm_auth_header(self, mock_retry_using_http_ntlm_auth):
        auth = HttpNtlmAuth(self.test_server_username, self.test_server_password)
        response = requests.Response()
        response.status_code = 401
        response.headers["WWW-Authenticate"] = "NTLM"
        new_response = auth.response_hook(response)
        mock_retry_using_http_ntlm_auth.assert_called_once_with(
            "www-authenticate",
            "Authorization",
            response,
            "NTLM",
            {}
        )
        assert new_response is not response

    @mock.patch("requests_ntlm2.auth.HttpNtlmAuth.retry_using_http_ntlm_auth")
    def test_response_hook__http_401_negotiate_auth_header(self, mock_retry_using_http_ntlm_auth):
        auth = HttpNtlmAuth(self.test_server_username, self.test_server_password)
        response = requests.Response()
        response.status_code = 401
        response.headers["WWW-Authenticate"] = "Negotiate"
        new_response = auth.response_hook(response)
        mock_retry_using_http_ntlm_auth.assert_called_once_with(
            "www-authenticate",
            "Authorization",
            response,
            "Negotiate",
            {}
        )
        assert new_response is not response

    @mock.patch("requests_ntlm2.auth.HttpNtlmAuth.retry_using_http_ntlm_auth")
    def test_response_hook__http_407_basic_auth_header(self, mock_retry_using_http_ntlm_auth):
        auth = HttpNtlmAuth(self.test_server_username, self.test_server_password)
        response = requests.Response()
        response.status_code = 407
        response.headers["Proxy-Authenticate"] = "Basic"
        new_response = auth.response_hook(response)
        mock_retry_using_http_ntlm_auth.assert_not_called()
        assert new_response is response

    @mock.patch("requests_ntlm2.auth.HttpNtlmAuth.retry_using_http_ntlm_auth")
    def test_response_hook__http_407_ntlm_auth_header(self, mock_retry_using_http_ntlm_auth):
        auth = HttpNtlmAuth(self.test_server_username, self.test_server_password)
        response = requests.Response()
        response.status_code = 407
        response.headers["Proxy-Authenticate"] = "NTLM"
        new_response = auth.response_hook(response)
        mock_retry_using_http_ntlm_auth.assert_called_once_with(
            "proxy-authenticate",
            "Proxy-Authorization",
            response,
            "NTLM",
            {}
        )
        assert new_response is not response

    @mock.patch("requests_ntlm2.auth.HttpNtlmAuth.retry_using_http_ntlm_auth")
    def test_response_hook__http_407_negotiate_auth_header(self, mock_retry_using_http_ntlm_auth):
        auth = HttpNtlmAuth(self.test_server_username, self.test_server_password)
        response = requests.Response()
        response.status_code = 407
        response.headers["Proxy-Authenticate"] = "Negotiate"
        new_response = auth.response_hook(response)
        mock_retry_using_http_ntlm_auth.assert_called_once_with(
            "proxy-authenticate",
            "Proxy-Authorization",
            response,
            "Negotiate",
            {}
        )
        assert new_response is not response

    def test_requests_ntlm(self):
        for auth_type in self.auth_types:
            res = requests.get(
                url=self.test_server_url + auth_type,
                auth=HttpNtlmAuth(
                    self.test_server_username, self.test_server_password
                ),
            )
            assert res.status_code == 200

    def test_history_is_preserved(self):
        for auth_type in self.auth_types:
            res = requests.get(
                url=self.test_server_url + auth_type,
                auth=HttpNtlmAuth(
                    self.test_server_username, self.test_server_password
                ),
            )

            assert len(res.history) == 2

    def test_new_requests_are_used(self):
        for auth_type in self.auth_types:
            res = requests.get(
                url=self.test_server_url + auth_type,
                auth=HttpNtlmAuth(
                    self.test_server_username, self.test_server_password
                ),
            )

            assert res.history[0].request is not res.history[1].request
            assert res.history[0].request is not res.request

    def test_username_parse_backslash(self):
        test_user = "domain\\user"
        expected_domain = "DOMAIN"
        expected_user = "user"

        context = HttpNtlmAuth(test_user, "pass")

        actual_domain = context.domain
        actual_user = context.username

        assert actual_domain == expected_domain
        assert actual_user == expected_user

    def test_username_parse_at(self):
        test_user = "user@domain.com"
        # UPN format should not be split,
        # since "stuff after @" not always == domain
        # (eg, email address with alt UPN suffix)
        expected_domain = ""
        expected_user = "user@domain.com"

        context = HttpNtlmAuth(test_user, "pass")

        actual_domain = context.domain
        actual_user = context.username

        assert actual_domain == expected_domain
        assert actual_user == expected_user

    def test_username_parse_no_domain(self):
        test_user = "user"
        expected_domain = ""
        expected_user = "user"

        context = HttpNtlmAuth(test_user, "pass")

        actual_domain = context.domain
        actual_user = context.username

        assert actual_domain == expected_domain
        assert actual_user == expected_user

    def test_retry_using_http_ntlm_auth(self):
        auth = HttpNtlmAuth(self.test_server_username, self.test_server_password)
        response = requests.Response()
        response.request = requests.Request(headers={"Proxy-Authenticate": "NTLM bla bla"})
        response.status_code = 407
        response.headers["Proxy-Authenticate"] = "NTLM"
        result = auth.retry_using_http_ntlm_auth(
            "foobar",
            "Proxy-Authenticate",
            response,
            "foobar",
            {}
        )
        assert result is response

        fp = BytesIO(
            b"Proxy-Authenticate: NTLM TlRMTVNTUAACAAAABgAGADgAAAAGgokAyYpGWqVMA/QAAAAAAAAA"
            b"AH4AfgA+AAAABQCTCAAAAA9ERVROU1cCAAwARABFAFQATgBTAFcAAQAaAFMARwAtADQAOQAxADMAM"
            b"wAwADAAMAAwADkABAAUAEQARQBUAE4AUwBXAC4AVwBJAE4AAwAwAHMAZwAtADQAOQAxADMAMwAwAD"
            b"AAMAAwADkALgBkAGUAdABuAHMAdwAuAHcAaQBuAAAAAAA=\r\n"
            b"Connection: Keep-Alive\r\n"
            b"Proxy-Connection: Keep-Alive\r\n"
            b"Server: nginx\r\n"
            b"\r\n"
            b"this is the body\r\n"
            b"\r\n"
        )
        content_length = len(fp.read())
        assert fp.read() == b""

        response = requests.Response()
        response.request = requests.Request(headers={})
        response.request.copy = mock.MagicMock()
        response.status_code = 407
        response.request.body = fp
        response.request.headers["Content-Length"] = str(content_length)

        response2 = requests.Response()
        response2.request = requests.Request(headers={})
        response2.raw = mock.MagicMock()
        response2.request.copy = mock.MagicMock()
        response2.headers = {"set-cookie": "test-cookie", "foobar": "baz", "foobar2": "bla"}
        response2.connection = mock.MagicMock()

        response.raw = mock.MagicMock()
        response.connection = mock.MagicMock()
        response.connection.send = mock.MagicMock(return_value=response2)
        func_spec = "requests_ntlm2.dance.HttpNtlmContext.get_authenticate_header"
        with mock.patch(func_spec) as mock_auth_header:
            result = auth.retry_using_http_ntlm_auth(
                "foobar",
                "Proxy-Authenticate",
                response,
                "NTLM",
                {}
            )
            assert result is response2.connection.send.return_value
            mock_auth_header.assert_called()

    def test_retry_using_http_ntlm_auth__no_content_length(self):
        auth = HttpNtlmAuth(
            self.test_server_username,
            self.test_server_password,
            send_cbt=False
        )
        response = requests.Response()
        response.request = requests.Request(headers={"Proxy-Authenticate": "NTLM bla bla"})
        response.status_code = 407
        response.headers["Proxy-Authenticate"] = "NTLM"
        result = auth.retry_using_http_ntlm_auth(
            "foobar",
            "Proxy-Authenticate",
            response,
            "foobar",
            {}
        )
        assert result is response

        fp = BytesIO(
            b"Proxy-Authenticate: NTLM TlRMTVNTUAACAAAABgAGADgAAAAGgokAyYpGWqVMA/QAAAAAAAAA"
            b"AH4AfgA+AAAABQCTCAAAAA9ERVROU1cCAAwARABFAFQATgBTAFcAAQAaAFMARwAtADQAOQAxADMAM"
            b"wAwADAAMAAwADkABAAUAEQARQBUAE4AUwBXAC4AVwBJAE4AAwAwAHMAZwAtADQAOQAxADMAMwAwAD"
            b"AAMAAwADkALgBkAGUAdABuAHMAdwAuAHcAaQBuAAAAAAA=\r\n"
            b"Connection: Keep-Alive\r\n"
            b"Proxy-Connection: Keep-Alive\r\n"
            b"Server: nginx\r\n"
            b"\r\n"
            b"this is the body\r\n"
            b"\r\n"
        )

        response = requests.Response()
        response.request = requests.Request(headers={})
        response.request.copy = mock.MagicMock()
        response.status_code = 407
        response.request.body = fp

        response2 = requests.Response()
        response2.request = requests.Request(headers={})
        response2.raw = mock.MagicMock()
        response2.request.copy = mock.MagicMock()
        response2.headers = {"set-cookie": "test-cookie", "foobar": "baz", "foobar2": "bla"}
        response2.connection = mock.MagicMock()

        response.raw = mock.MagicMock()
        response.connection = mock.MagicMock()
        response.connection.send = mock.MagicMock(return_value=response2)
        func_spec = "requests_ntlm2.dance.HttpNtlmContext.get_authenticate_header"
        with mock.patch(func_spec) as mock_auth_header:
            result = auth.retry_using_http_ntlm_auth(
                "foobar",
                "Proxy-Authenticate",
                response,
                "NTLM",
                {}
            )
            assert result is response2.connection.send.return_value
            mock_auth_header.assert_called()

    def test_retry_using_http_ntlm_auth__big_content_length(self):
        auth = HttpNtlmAuth(self.test_server_username, self.test_server_password)
        response = requests.Response()
        response.request = requests.Request(headers={"Proxy-Authenticate": "NTLM bla bla"})
        response.status_code = 407
        response.headers["Proxy-Authenticate"] = "NTLM"
        result = auth.retry_using_http_ntlm_auth(
            "foobar",
            "Proxy-Authenticate",
            response,
            "foobar",
            {}
        )
        assert result is response

        fp = StringIO(
            "Proxy-Authenticate: NTLM TlRMTVNTUAACAAAABgAGADgAAAAGgokAyYpGWqVMA/QAAAAAAAAA"
            "AH4AfgA+AAAABQCTCAAAAA9ERVROU1cCAAwARABFAFQATgBTAFcAAQAaAFMARwAtADQAOQAxADMAM"
            "wAwADAAMAAwADkABAAUAEQARQBUAE4AUwBXAC4AVwBJAE4AAwAwAHMAZwAtADQAOQAxADMAMwAwAD"
            "AAMAAwADkALgBkAGUAdABuAHMAdwAuAHcAaQBuAAAAAAA=\r\n"
            "Connection: Keep-Alive\r\n"
            "Proxy-Connection: Keep-Alive\r\n"
            "Server: nginx\r\n"
            "\r\n"
            "this is the body\r\n"
            "\r\n"
        )
        content_length = len(fp.read())
        assert fp.read() == ""

        response = requests.Response()
        response.request = requests.Request(headers={})
        response.request.copy = mock.MagicMock()
        response.status_code = 407
        response.request.body = fp
        response.request.headers["Content-Length"] = str(content_length * 2)

        response2 = requests.Response()
        response2.request = requests.Request(headers={})
        response2.raw = mock.MagicMock()
        response2.request.copy = mock.MagicMock()
        response2.headers = {"set-cookie": "test-cookie", "foobar": "baz", "foobar2": "bla"}
        response2.connection = mock.MagicMock()

        response.raw = mock.MagicMock()
        response.connection = mock.MagicMock()
        response.connection.send = mock.MagicMock(return_value=response2)
        func_spec = "requests_ntlm2.dance.HttpNtlmContext.get_authenticate_header"
        with mock.patch(func_spec) as mock_auth_header:
            result = auth.retry_using_http_ntlm_auth(
                "foobar",
                "Proxy-Authenticate",
                response,
                "NTLM",
                {}
            )
            assert result is response2.connection.send.return_value
            mock_auth_header.assert_called()


class TestAuthType:
    def test_get_auth_type_from_header(self):
        auth_type = get_auth_type_from_header("Negotiate, NTLM")
        assert auth_type == "NTLM"
        auth_type = get_auth_type_from_header("Negotiate")
        assert auth_type == "Negotiate"
        auth_type = get_auth_type_from_header("Basic")
        assert auth_type is None
