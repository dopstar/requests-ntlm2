import unittest

import mock
import requests.adapters
import requests.sessions
from requests.packages.urllib3.connection import HTTPConnection, HTTPSConnection

import requests_ntlm2.adapters
import requests_ntlm2.connection


class TestHttpProxyAdapter(unittest.TestCase):
    def test_init(self):
        adapter = requests_ntlm2.adapters.HttpProxyAdapter()
        self.assertIsInstance(adapter, requests_ntlm2.adapters.HttpProxyAdapter)
        self.assertIsInstance(adapter, requests.adapters.HTTPAdapter)

    def test__add_host_header(self):
        adapter = requests_ntlm2.adapters.HttpProxyAdapter()
        request = requests.Request(url="http://github.com:80")
        self.assertIsNone(request.headers.get("Host"))

        adapter._add_host_header(request)
        self.assertIsNotNone(request.headers.get("Host"))
        self.assertEqual(request.headers["Host"], "github.com")

        request = requests.Request(url="https://github.com:443")
        self.assertIsNone(request.headers.get("Host"))
        adapter._add_host_header(request)
        self.assertIsNone(request.headers.get("Host"))

    def test__is_valid_host_header(self):
        adapter = requests_ntlm2.adapters.HttpProxyAdapter()
        request = requests.Request()
        self.assertFalse(adapter._is_valid_host_header(request))

        request.url = "https://google.com:443"
        request.headers["Host"] = "google.com:443"
        self.assertTrue(adapter._is_valid_host_header(request))

        request.url = "https://google.com:8080"
        self.assertFalse(adapter._is_valid_host_header(request))

    def test__remove_host_header(self):
        adapter = requests_ntlm2.adapters.HttpProxyAdapter()
        request = requests.Request()
        self.assertIsNone(adapter._remove_host_header(request))
        self.assertIsNone(request.headers.get("Host"))

        request.headers["Host"] = "google.com:443"
        self.assertIsNone(adapter._remove_host_header(request))
        self.assertIsNone(request.headers.get("Host"))

    @mock.patch("requests_ntlm2.adapters.HttpProxyAdapter._add_host_header")
    def test_add_headers(self, mock_add_host_header):
        adapter = requests_ntlm2.adapters.HttpProxyAdapter()
        request = requests.Request(url="http://github.com:80")
        self.assertIsNone(adapter.add_headers(request))
        mock_add_host_header.assert_called_once_with(request)


class TestHttpNtlmAdapter(unittest.TestCase):
    @mock.patch("requests_ntlm2.adapters.HttpNtlmAdapter._teardown")
    @mock.patch("requests_ntlm2.adapters.HttpNtlmAdapter._setup")
    def test_init(self, mock_setup, mock_teardown):
        adapter = requests_ntlm2.adapters.HttpNtlmAdapter("username", "password")
        self.assertIsInstance(adapter, requests_ntlm2.adapters.HttpNtlmAdapter)
        self.assertIsInstance(adapter, requests_ntlm2.adapters.HttpProxyAdapter)
        self.assertIsInstance(adapter, requests.adapters.HTTPAdapter)
        mock_setup.assert_called_once_with("username", "password")
        mock_teardown.assert_not_called()

    @mock.patch("requests_ntlm2.adapters.HttpNtlmAdapter._teardown")
    @mock.patch("requests_ntlm2.adapters.HttpNtlmAdapter._setup")
    def close(self, mock_setup, mock_teardown):
        adapter = requests_ntlm2.adapters.HttpNtlmAdapter("username", "password")
        self.assertIsNone(adapter.close())
        mock_setup.assert_called_once_with("username", "password")
        mock_teardown.assert_called_once()

    @mock.patch("requests_ntlm2.connection.HTTPSConnection.set_ntlm_auth_credentials")
    def test__setup(self, mock_set_ntlm_auth_credentials):
        from requests.packages.urllib3.poolmanager import pool_classes_by_scheme
        adapter = requests_ntlm2.adapters.HttpNtlmAdapter("username", "password")
        mock_set_ntlm_auth_credentials.assert_called_once_with("username", "password")

        http_conn_cls = pool_classes_by_scheme["http"].ConnectionCls
        https_conn_cls = pool_classes_by_scheme["https"].ConnectionCls
        self.assertTrue(http_conn_cls, requests_ntlm2.connection.HTTPConnection)
        self.assertTrue(https_conn_cls, requests_ntlm2.connection.HTTPSConnection)
        adapter.close()

    @mock.patch("requests_ntlm2.connection.HTTPSConnection.clear_ntlm_auth_credentials")
    @mock.patch("requests_ntlm2.connection.HTTPSConnection.set_ntlm_auth_credentials")
    def test_close(self, set_ntlm_auth_credentials, clear_ntlm_auth_credentials):
        from requests.packages.urllib3.poolmanager import pool_classes_by_scheme
        adapter = requests_ntlm2.adapters.HttpNtlmAdapter("username2", "password")
        set_ntlm_auth_credentials.assert_called_once_with("username2", "password")

        http_conn_cls = pool_classes_by_scheme["http"].ConnectionCls
        https_conn_cls = pool_classes_by_scheme["https"].ConnectionCls
        self.assertTrue(http_conn_cls, requests_ntlm2.connection.HTTPConnection)
        self.assertTrue(https_conn_cls, requests_ntlm2.connection.HTTPSConnection)

        adapter.close()
        clear_ntlm_auth_credentials.assert_called_once()
        http_conn_cls = pool_classes_by_scheme["http"].ConnectionCls
        https_conn_cls = pool_classes_by_scheme["https"].ConnectionCls
        self.assertTrue(http_conn_cls, HTTPConnection)
        self.assertTrue(https_conn_cls, HTTPSConnection)
