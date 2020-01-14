import unittest

from requests_ntlm2.connection import VerifiedHTTPSConnection


class TestVerifiedHTTPSConnection(unittest.TestCase):

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
