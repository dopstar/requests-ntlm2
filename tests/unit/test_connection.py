import socket
import sys
import tempfile
import unittest

import faker
import mock
from six.moves.http_client import LineTooLong

from requests_ntlm2.connection import _MAXLINE, VerifiedHTTPSConnection


try:
    from StringIO import StringIO as BytesIO  # py2
except ImportError:
    from io import BytesIO  # py3


class TestVerifiedHTTPSConnection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake = faker.Factory.create()

    def setUp(self):
        self.conn = VerifiedHTTPSConnection("srv-93.shaw.com", port=6789)
        self.tunnel_host = "email-20.henry-burgess.com"
        self.tunnel_port = 8080
        self.conn._tunnel_host = self.tunnel_host
        self.conn._tunnel_port = self.tunnel_port
        self.conn._tunnel_headers = {}

    def tearDown(self):
        self.conn.clear_ntlm_auth_credentials()
        self.conn.close()

    def test_init(self):
        VerifiedHTTPSConnection.ntlm_compatibility = None
        conn = VerifiedHTTPSConnection("srv-93.shaw.com", port=6789)
        self.assertIsNone(VerifiedHTTPSConnection.ntlm_compatibility)
        self.assertEqual(conn.ntlm_compatibility, 3)

    def test__get_header_bytes(self):
        proxy_auth_header = "Basic blablablablajhaskdfgjshd"
        headers = self.conn._get_header_bytes(proxy_auth_header=proxy_auth_header)
        self.assertEqual(
            headers,
            (
                "CONNECT {host}:{port} HTTP/1.1\r\n"
                "Host: {host}:{port}\r\n"
                "Proxy-Authorization: {proxy_header}\r\n"
                "Proxy-Connection: Keep-Alive\r\n"
                "\r\n"
            ).format(
                proxy_header=proxy_auth_header,
                host=self.tunnel_host,
                port=self.tunnel_port
            ).encode(
                "latin1"
            )
        )
        self.assertIsInstance(headers, bytes)

    def test__get_header_bytes__no_proxy_header(self):
        headers = self.conn._get_header_bytes()
        self.assertEqual(
            headers,
            (
                "CONNECT {host}:{port} HTTP/1.1\r\n"
                "Host: {host}:{port}\r\n"
                "Proxy-Connection: Keep-Alive\r\n"
                "\r\n"
            ).format(
                host=self.tunnel_host,
                port=self.tunnel_port
            ).encode(
                "latin1"
            )
        )
        self.assertIsInstance(headers, bytes)

    def test__tunnel__no_credentials(self):
        with self.assertRaises(AttributeError):
            self.conn._tunnel()

    @mock.patch("requests_ntlm2.connection.select.select")
    @mock.patch("requests_ntlm2.connection.VerifiedHTTPSConnection._get_response")
    @mock.patch("requests_ntlm2.connection.VerifiedHTTPSConnection.send")
    def test__tunnel__line_too_long(self, mock_send, mock_get_response, mock_select):
        fp = BytesIO(
            b"Proxy-Authenticate: NTLM TlRMTVNTUAACAAAABgAGADgAAAAGgokAyYpGWqVMA/QAAAAAAAAA"
            b"AH4AfgA+AAAABQCTCAAAAA9ERVROU1cCAAwARABFAFQATgBTAFcAAQAaAFMARwAtADQAOQAxADMAM"
            b"wAwADAAMAAwADkABAAUAEQARQBUAE4AUwBXAC4AVwBJAE4AAwAwAHMAZwAtADQAOQAxADMAMwAwAD"
            b"AAMAAwADkALgBkAGUAdABuAHMAdwAuAHcAaQBuAAAAAAA=\r\n"
            b"Connection: Keep-Alive\r\n"
            b"Proxy-Connection: Keep-Alive\r\n"
            b"Server: nginx\r\n"
            b"Info: x%s\r\n"
            b"\r\n"
            b"this is the body\r\n"
            b"\r\n" % (b"x" * _MAXLINE)
        )
        response = type("Response", (), dict(fp=fp))
        mock_get_response.return_value = "HTTP/1.1", 407, "Proxy Authentication Required", response
        mock_select.return_value = [(True), (), ()]
        self.conn.set_ntlm_auth_credentials(r"DOMAIN\username", "password")

        with self.assertRaises(LineTooLong):
            self.conn._tunnel()

        fp.seek(0)
        mock_get_response.return_value = "HTTP/1.1", 200, "OK", response
        self.conn.set_ntlm_auth_credentials(r"DOMAIN\username", "password")
        with self.assertRaises(LineTooLong):
            self.conn._tunnel()

    @mock.patch("requests_ntlm2.connection.select.select")
    @mock.patch("requests_ntlm2.connection.VerifiedHTTPSConnection._get_response")
    @mock.patch("requests_ntlm2.connection.VerifiedHTTPSConnection.send")
    def test_tunnel__no_headers(self, mock_send, mock_get_response, mock_select):
        fp = BytesIO()
        response = type("Response", (), dict(fp=fp))

        mock_get_response.return_value = "HTTP/1.1", 407, "Proxy Authentication Required", response
        mock_select.return_value = [(True), (), ()]
        username = self.fake.user_name()
        password = self.fake.password()
        self.conn.set_ntlm_auth_credentials(username, password)

        error_msg = "Tunnel connection failed: 407 Proxy Authentication Required"
        with self.assertRaisesRegexp(socket.error, error_msg):
            self.conn._tunnel()

        mock_get_response.assert_called()
        mock_send.assert_called()
        self.assertEqual(mock_get_response.call_count, 2)
        self.assertEqual(mock_send.call_count, 2)

    @mock.patch("requests_ntlm2.connection.select.select")
    @mock.patch("requests_ntlm2.connection.VerifiedHTTPSConnection._get_response")
    @mock.patch("requests_ntlm2.connection.VerifiedHTTPSConnection.send")
    def test_tunnel__no_proxy_auth_required(self, mock_send, mock_get_response, mock_select):
        fp = BytesIO()
        response = type("Response", (), dict(fp=fp))

        mock_get_response.return_value = "HTTP/1.1", 200, "Success", response
        mock_select.return_value = [(True), (), ()]
        username = self.fake.user_name()
        password = self.fake.password()
        self.conn.set_ntlm_auth_credentials(username, password)

        self.conn._tunnel()

        mock_get_response.assert_called()
        mock_send.assert_called()
        self.assertEqual(mock_get_response.call_count, 1)
        self.assertEqual(mock_send.call_count, 1)

    @mock.patch("requests_ntlm2.connection.select.select")
    @mock.patch("requests_ntlm2.connection.VerifiedHTTPSConnection._get_response")
    @mock.patch("requests_ntlm2.connection.VerifiedHTTPSConnection.send")
    def test_tunnel(self, mock_send, mock_get_response, mock_select):
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

        response = type("Response", (), dict(fp=fp))

        mock_select.return_value = [(True), (), ()]

        def return_407():
            return "HTTP/1.1", 407, "Proxy Authentication Required", response

        def return_200():
            return "HTTP/1.1", 200, "Success", response

        mock_get_response.side_effect = return_407(), return_200()
        username = self.fake.user_name()
        password = self.fake.password()
        self.conn.set_ntlm_auth_credentials(username, password)

        self.conn._tunnel()

        mock_get_response.assert_called()
        mock_send.assert_called()
        self.assertEqual(mock_get_response.call_count, 2)
        self.assertEqual(mock_send.call_count, 2)

    @mock.patch("requests_ntlm2.connection.select.select")
    @mock.patch("requests_ntlm2.connection.VerifiedHTTPSConnection._get_response")
    @mock.patch("requests_ntlm2.connection.VerifiedHTTPSConnection.send")
    def test_tunnel__no_continue_read_headers(self, mock_send, mock_get_response, mock_select):
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

        response = type("Response", (), dict(fp=fp))

        mock_select.return_value = [(True), (), ()]

        def return_407():
            return "HTTP/1.1", 407, "Proxy Authentication Required", response

        def return_200():
            return "HTTP/1.1", 200, "Success", response

        mock_get_response.side_effect = return_407(), return_200()
        username = self.fake.user_name()
        password = self.fake.password()
        self.conn.set_ntlm_auth_credentials(username, password)

        continue_reading_headers = self.conn._continue_reading_headers
        self.conn._continue_reading_headers = False
        self.conn._tunnel()

        mock_get_response.assert_called()
        mock_send.assert_called()
        self.assertEqual(mock_get_response.call_count, 2)
        self.assertEqual(mock_send.call_count, 2)
        self.conn._continue_reading_headers = continue_reading_headers

    @mock.patch("requests_ntlm2.connection.select.select")
    @mock.patch("requests_ntlm2.connection.VerifiedHTTPSConnection._get_response")
    @mock.patch("requests_ntlm2.connection.VerifiedHTTPSConnection.send")
    def test_tunnel_only_headers(self, mock_send, mock_get_response, mock_select):
        fp = BytesIO(
            b"Proxy-Authenticate: NTLM TlRMTVNTUAACAAAABgAGADgAAAAGgokAyYpGWqVMA/QAAAAAAAAA"
            b"AH4AfgA+AAAABQCTCAAAAA9ERVROU1cCAAwARABFAFQATgBTAFcAAQAaAFMARwAtADQAOQAxADMAM"
            b"wAwADAAMAAwADkABAAUAEQARQBUAE4AUwBXAC4AVwBJAE4AAwAwAHMAZwAtADQAOQAxADMAMwAwAD"
            b"AAMAAwADkALgBkAGUAdABuAHMAdwAuAHcAaQBuAAAAAAA=\r\n"
            b"Connection: Keep-Alive\r\n"
            b"Proxy-Connection: Keep-Alive\r\n"
            b"\r\n"
        )

        response = type("Response", (), dict(fp=fp))

        mock_select.return_value = [(True), (), ()]

        def return_407():
            return "HTTP/1.1", 407, "authenticationrequired", response

        def return_200():
            return "HTTP/1.1", 200, "Success", response

        mock_get_response.side_effect = return_407(), return_200()
        username = self.fake.user_name()
        password = self.fake.password()
        self.conn.set_ntlm_auth_credentials(username, password)

        self.conn._tunnel()

        mock_get_response.assert_called()
        mock_send.assert_called()
        self.assertEqual(mock_get_response.call_count, 2)
        self.assertEqual(mock_send.call_count, 2)

    @mock.patch("requests.packages.urllib3.connection.VerifiedHTTPSConnection.response_class")
    def test__get_response(self, mock_response_class):
        mock_response_class.return_value._read_status.return_value = (1, 2, 3)
        response = self.conn._get_response()
        self.assertIsInstance(response, tuple)
        self.assertEqual(len(response), 4)
        self.assertEqual(response[:3], (1, 2, 3))

    @mock.patch("requests.packages.urllib3.connection.VerifiedHTTPSConnection.response_class")
    @mock.patch("requests_ntlm2.connection.VerifiedHTTPSConnection.handle_http09_response")
    def test__get_response__http09(self, mock_handle_http09_response, mock_response_class):
        mock_response_class.return_value._read_status.return_value = ("HTTP/0.9", 200, "")
        mock_handle_http09_response.return_value = None
        response = self.conn._get_response()
        self.assertIsInstance(response, tuple)
        self.assertEqual(len(response), 4)
        self.assertEqual(response[:3], ("HTTP/0.9", 200, ""))
        mock_handle_http09_response.assert_called_once()

    @mock.patch("requests.packages.urllib3.connection.VerifiedHTTPSConnection.response_class")
    @mock.patch("requests_ntlm2.connection.VerifiedHTTPSConnection.handle_http09_response")
    def test__get_response__http09_status(self, mock_handle_http09_response, mock_response_class):
        mock_response_class.return_value._read_status.return_value = ("HTTP/0.9", 200, "")
        mock_handle_http09_response.return_value = (10, 20, 30)
        response = self.conn._get_response()
        self.assertIsInstance(response, tuple)
        self.assertEqual(len(response), 4)
        self.assertEqual(response[:3], (10, 20, 30))
        mock_handle_http09_response.assert_called_once()

    def test_handle_http09(self):
        fp = BytesIO(
            b"<!DOCTYPE html>\r\n"
            b"<html class='#{theme}' lang='en'>\r\n"
            b"<head data-theme='#{theme}' data-revision='865b887'>\r\n"
            b"<meta charset='utf-8'/>\r\n"
            b"<meta http-equiv='X-UA-Compatible' content='IE=edge'/>\r\n"
            b"<meta name='viewport' content='width=device-width, initial-scale=1'/>\r\n"
            b"<base/>\r\n"
            b"<title>401 Unauthorised</title><!--[if lt IE 9]>\r\n"
            b"<script src=\'https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js\' type=\'text/javascript\' />\r\n"  # noqa
            b"<script src=\'https://oss.maxcdn.com/respond/1.4.2/respond.min.js\' type=\'text/javascript\' />\r\n"  # noqa
            b"<![endif]-->\r\n"
            b"<script type='text/javascript'>\r\n"
            b"function showURL()\r\n"
            b"{\r\n"
            b"document.write('<a href=\"mailto:itweb-admin@abc.def.com?subject=Proxy Authentication\">EDConnect</a>');\r\n"  # noqa
            b"}\r\n"
            b"\r\n"
            b"function URL()\r\n"
            b"{\r\n"
            b"document.write(document.URL);\r\n"
            b"}\r\n"
            b"</script>\r\n"
            b"<style media='screen'>\r\n"
            b"</div>\r\n"
            b"</div>\r\n"
            b"</div>\r\n"
            b"</aside></body>\r\n"
            b"</html>\r\n"
            b"HTTP/1.1 200 Connection established\r\n"
        )
        response = type("Response", (), dict(fp=fp))
        status_line = self.conn.handle_http09_response(response)
        self.assertEqual(status_line, (b"HTTP/1.1", 200, b"Connection established\r\n"))

    def test_handle_http09__worst_case(self):
        fp = BytesIO(
            b"<!DOCTYPE html>\r\n"
            b"<html class='#{theme}' lang='en'>\r\n"
            b"<head data-theme='#{theme}' data-revision='865b887'>\r\n"
            b"<meta charset='utf-8'/>\r\n"
            b"<meta http-equiv='X-UA-Compatible' content='IE=edge'/>\r\n"
            b"<meta name='viewport' content='width=device-width, initial-scale=1'/>\r\n"
            b"<base/>\r\n"
            b"<title>401 Unauthorised</title><!--[if lt IE 9]>\r\n"
            b"<script src=\'https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js\' type=\'text/javascript\' />\r\n"  # noqa
            b"<script src=\'https://oss.maxcdn.com/respond/1.4.2/respond.min.js\' type=\'text/javascript\' />\r\n"  # noqa
            b"<![endif]-->\r\n"
            b"<script type='text/javascript'>\r\n"
            b"function showURL()\r\n"
            b"{\r\n"
            b"document.write('<a href=\"mailto:itweb-admin@abc.def.com?subject=Proxy Authentication\">EDConnect</a>');\r\n"  # noqa
            b"}\r\n"
            b"\r\n"
            b"function URL()\r\n"
            b"{\r\n"
            b"document.write(document.URL);\r\n"
            b"}\r\n"
            b"</script>\r\n"
            b"<style media='screen'>\r\n"
            b"</div>\r\n"
            b"</div>\r\n"
            b"</div>\r\n"
            b"</aside></body>\r\n"
            b"</html>\r\n"
        )
        response = type("Response", (), dict(fp=fp))
        status_line = self.conn.handle_http09_response(response)
        self.assertIsNone(status_line)

    def test__read_response_line_if_ready(self):
        data = (
            b"<!DOCTYPE html>\r\n"
            b"<html class='#{theme}' lang='en'>\r\n"
            b"<head data-theme='#{theme}' data-revision='865b887'>\r\n"
            b"<meta charset='utf-8'/>\r\n"
            b"<meta http-equiv='X-UA-Compatible' content='IE=edge'/>\r\n"
            b"<meta name='viewport' content='width=device-width, initial-scale=1'/>\r\n"
            b"<base/>\r\n"
            b"<title>401 Unauthorised</title><!--[if lt IE 9]>\r\n"
            b"<script src=\'https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js\' type=\'text/javascript\' />\r\n"  # noqa
            b"<script src=\'https://oss.maxcdn.com/respond/1.4.2/respond.min.js\' type=\'text/javascript\' />\r\n"  # noqa
            b"<![endif]-->\r\n"
            b"<script type='text/javascript'>\r\n"
            b"function showURL()\r\n"
            b"{\r\n"
            b"document.write('<a href=\"mailto:itweb-admin@abc.def.com?subject=Proxy Authentication\">EDConnect</a>');\r\n"  # noqa
            b"}\r\n"
            b"\r\n"
            b"function URL()\r\n"
            b"{\r\n"
            b"document.write(document.URL);\r\n"
            b"}\r\n"
            b"</script>\r\n"
            b"<style media='screen'>\r\n"
            b"</div>\r\n"
            b"</div>\r\n"
            b"</div>\r\n"
            b"</aside></body>\r\n"
            b"</html>\r\n"
        )
        with tempfile.TemporaryFile() as fd:
            fd.write(data)
            fd.seek(0)
            response = type("Response", (), dict(fp=fd))
            line = self.conn._read_response_line_if_ready(response)
            assert line == b"<!DOCTYPE html>\r\n"

        with tempfile.TemporaryFile() as fd:
            fd.write(data)
            fd.seek(0)
            response = type("Response", (), dict(fp=fd))
            with mock.patch("select.select", return_value=((), (), ())) as mock_select:
                line = self.conn._read_response_line_if_ready(response)
                assert line is None
                mock_select.assert_called_once_with([response.fp], (), (), 0.1)

    def test__flush_response_buffer(self):
        data = (
            b"<!DOCTYPE html>\r\n"
            b"<html class='#{theme}' lang='en'>\r\n"
            b"<head data-theme='#{theme}' data-revision='865b887'>\r\n"
            b"<meta charset='utf-8'/>\r\n"
            b"<meta http-equiv='X-UA-Compatible' content='IE=edge'/>\r\n"
            b"<meta name='viewport' content='width=device-width, initial-scale=1'/>\r\n"
            b"<base/>\r\n"
            b"<title>401 Unauthorised</title><!--[if lt IE 9]>\r\n"
            b"<script src=\'https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js\' type=\'text/javascript\' />\r\n"  # noqa
            b"<script src=\'https://oss.maxcdn.com/respond/1.4.2/respond.min.js\' type=\'text/javascript\' />\r\n"  # noqa
            b"<![endif]-->\r\n"
            b"<script type='text/javascript'>\r\n"
            b"function showURL()\r\n"
            b"{\r\n"
            b"document.write('<a href=\"mailto:itweb-admin@abc.def.com?subject=Proxy Authentication\">EDConnect</a>');\r\n"  # noqa
            b"}\r\n"
            b"\r\n"
            b"function URL()\r\n"
            b"{\r\n"
            b"document.write(document.URL);\r\n"
            b"}\r\n"
            b"</script>\r\n"
            b"<style media='screen'>\r\n"
            b"</div>\r\n"
            b"</div>\r\n"
            b"</div>\r\n"
            b"</aside></body>\r\n"
            b"</html>\r\n"
        )
        with tempfile.TemporaryFile() as fd:
            fd.write(data)
            fd.seek(0)
            response = type("Response", (), dict(fp=fd))
            result = self.conn._flush_response_buffer(response)
            assert result is None
            assert fd.read() == b""

        with tempfile.TemporaryFile() as fd:
            fd.write(data)
            fd.seek(0)
            response = type("Response", (), dict(fp=fd))
            with mock.patch("select.select", return_value=((), (), ())) as mock_select:
                result = self.conn._flush_response_buffer(response)
                assert result is None
                mock_select.assert_called_once_with([response.fp], (), (), 0.1)
                assert fd.read() == data


def test_import_error():
    with mock.patch("requests_ntlm2.core.noop") as mock_noop:
        mock_noop.side_effect = ImportError()
        import requests_ntlm2.connection  # noqa - this is ensure sys.modules key is present
        del sys.modules["requests_ntlm2.connection"]
        import requests_ntlm2.connection  # noqa
        assert (
            requests_ntlm2.connection.HTTPSConnection is requests_ntlm2.connection.DummyConnection
        )
