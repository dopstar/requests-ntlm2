import socket
import unittest

import faker
import mock

from requests_ntlm2.connection import VerifiedHTTPSConnection


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
        self.conn.close()

    def test__get_header_bytes(self):
        proxy_auth_header = "Basic blablablablajhaskdfgjshd"
        headers = self.conn._get_header_bytes(proxy_auth_header=proxy_auth_header)
        self.assertEqual(
            headers,
            (
                "CONNECT {host}:{port} HTTP/1.0\r\n"
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
                "CONNECT {host}:{port} HTTP/1.0\r\n"
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

    @mock.patch("requests_ntlm2.connection.VerifiedHTTPSConnection._get_response")
    @mock.patch("requests_ntlm2.connection.VerifiedHTTPSConnection.send")
    def test_tunnel__no_headers(self, mock_send, mock_get_response):
        fp = BytesIO()
        response = type("Response", (), dict(fp=fp))

        mock_get_response.return_value = "HTTP/1.1", 407, "Proxy Authentication Required", response
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

    @mock.patch("requests_ntlm2.connection.VerifiedHTTPSConnection._get_response")
    @mock.patch("requests_ntlm2.connection.VerifiedHTTPSConnection.send")
    def test_tunnel__no_proxy_auth_required(self, mock_send, mock_get_response):
        fp = BytesIO()
        response = type("Response", (), dict(fp=fp))

        mock_get_response.return_value = "HTTP/1.1", 200, "Success", response
        username = self.fake.user_name()
        password = self.fake.password()
        self.conn.set_ntlm_auth_credentials(username, password)

        self.conn._tunnel()

        mock_get_response.assert_called()
        mock_send.assert_called()
        self.assertEqual(mock_get_response.call_count, 1)
        self.assertEqual(mock_send.call_count, 1)

    @mock.patch("requests_ntlm2.connection.VerifiedHTTPSConnection._get_response")
    @mock.patch("requests_ntlm2.connection.VerifiedHTTPSConnection.send")
    def test_tunnel(self, mock_send, mock_get_response):
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
