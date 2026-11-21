from unittest import mock

import requests.adapters
import requests.sessions
from requests.packages.urllib3.connection import HTTPConnection, HTTPSConnection

from requests_ntlm2.proxy import connection
from requests_ntlm2.proxy.adapters.base import HttpProxyAdapter
from requests_ntlm2.proxy.adapters.ntlm import HttpNtlmAdapter


class TestHttpNtlmAdapter:
    @mock.patch("requests_ntlm2.proxy.adapters.ntlm.HttpNtlmAdapter._teardown")
    @mock.patch("requests_ntlm2.proxy.adapters.ntlm.HttpNtlmAdapter._setup")
    def test_init(self, mock_setup, mock_teardown):
        adapter = HttpNtlmAdapter("username", "password")
        assert isinstance(adapter, HttpNtlmAdapter)
        assert isinstance(adapter, HttpProxyAdapter)
        assert isinstance(adapter, requests.adapters.HTTPAdapter)
        mock_setup.assert_called_once_with("username", "password", 3, False, "HTTP/1.0")
        mock_teardown.assert_not_called()

    @mock.patch("requests_ntlm2.proxy.adapters.ntlm.HttpNtlmAdapter._teardown")
    @mock.patch("requests_ntlm2.proxy.adapters.ntlm.HttpNtlmAdapter._setup")
    def test_init__http_version(self, mock_setup, mock_teardown):
        adapter = HttpNtlmAdapter(
            "username",
            "password",
            proxy_tunnelling_http_version="HTTP/1.1"
        )
        assert isinstance(adapter, HttpNtlmAdapter)
        assert isinstance(adapter, HttpProxyAdapter)
        assert isinstance(adapter, requests.adapters.HTTPAdapter)
        mock_setup.assert_called_once_with("username", "password", 3, False, "HTTP/1.1")
        mock_teardown.assert_not_called()

    @mock.patch("requests_ntlm2.proxy.adapters.ntlm.HttpNtlmAdapter._teardown")
    @mock.patch("requests_ntlm2.proxy.adapters.ntlm.HttpNtlmAdapter._setup")
    def test_init__strict_mode(self, mock_setup, mock_teardown):
        adapter = HttpNtlmAdapter(
            "username",
            "password",
            ntlm_strict_mode=True
        )
        assert isinstance(adapter, HttpNtlmAdapter)
        assert isinstance(adapter, HttpProxyAdapter)
        assert isinstance(adapter, requests.adapters.HTTPAdapter)
        mock_setup.assert_called_once_with("username", "password", 3, True, "HTTP/1.0")
        mock_teardown.assert_not_called()

    @mock.patch("requests_ntlm2.proxy.adapters.ntlm.HttpNtlmAdapter._teardown")
    @mock.patch("requests_ntlm2.proxy.adapters.ntlm.HttpNtlmAdapter._setup")
    def close(self, mock_setup, mock_teardown):
        adapter = HttpNtlmAdapter("username", "password")
        assert adapter.close() is None
        mock_setup.assert_called_once_with("username", "password", 3)
        mock_teardown.assert_called_once()

    @mock.patch("requests_ntlm2.proxy.connection.HTTPSConnection.set_http_version")
    @mock.patch("requests_ntlm2.proxy.connection.HTTPSConnection.set_ntlm_auth_credentials")
    def test__setup(self, mock_set_ntlm_auth_credentials, mock_set_http_version):
        from requests.packages.urllib3.poolmanager import pool_classes_by_scheme
        adapter = HttpNtlmAdapter("username", "password")
        mock_set_ntlm_auth_credentials.assert_called_once_with("username", "password")
        mock_set_http_version.assert_called_once_with("HTTP/1.0")

        http_conn_cls = pool_classes_by_scheme["http"].ConnectionCls
        https_conn_cls = pool_classes_by_scheme["https"].ConnectionCls
        assert http_conn_cls is connection.HTTPConnection
        assert https_conn_cls is connection.HTTPSConnection
        adapter.close()

    @mock.patch("requests_ntlm2.proxy.connection.HTTPSConnection.set_http_version")
    @mock.patch("requests_ntlm2.proxy.connection.HTTPSConnection.set_ntlm_auth_credentials")
    def test__setup__http_version(self, mock_set_ntlm_auth_credentials, mock_set_http_version):
        from requests.packages.urllib3.poolmanager import pool_classes_by_scheme
        adapter = HttpNtlmAdapter(
            "username",
            "password",
            proxy_tunnelling_http_version="HTTP/1.1"
        )
        mock_set_ntlm_auth_credentials.assert_called_once_with("username", "password")
        mock_set_http_version.assert_called_once_with("HTTP/1.1")

        http_conn_cls = pool_classes_by_scheme["http"].ConnectionCls
        https_conn_cls = pool_classes_by_scheme["https"].ConnectionCls
        assert http_conn_cls is connection.HTTPConnection
        assert https_conn_cls is connection.HTTPSConnection
        adapter.close()

    @mock.patch("requests_ntlm2.proxy.connection.HTTPSConnection.set_http_version")
    def test__setup__without_http_version(self, set_http_version):
        adapter = HttpNtlmAdapter("username", "password", proxy_tunnelling_http_version=None)
        try:
            set_http_version.assert_not_called()
        finally:
            adapter.close()

    @mock.patch("requests_ntlm2.proxy.connection.HTTPSConnection.clear_http_version")
    @mock.patch("requests_ntlm2.proxy.connection.HTTPSConnection.set_http_version")
    @mock.patch("requests_ntlm2.proxy.connection.HTTPSConnection.clear_ntlm_auth_credentials")
    @mock.patch("requests_ntlm2.proxy.connection.HTTPSConnection.set_ntlm_auth_credentials")
    def test_close(
            self,
            set_ntlm_auth_credentials,
            clear_ntlm_auth_credentials,
            set_http_version,
            clear_http_version
    ):
        from requests.packages.urllib3.poolmanager import pool_classes_by_scheme
        adapter = HttpNtlmAdapter("username2", "password")
        set_ntlm_auth_credentials.assert_called_once_with("username2", "password")
        set_http_version.assert_called_once_with("HTTP/1.0")

        http_conn_cls = pool_classes_by_scheme["http"].ConnectionCls
        https_conn_cls = pool_classes_by_scheme["https"].ConnectionCls
        assert http_conn_cls is connection.HTTPConnection
        assert https_conn_cls is connection.HTTPSConnection

        adapter.close()
        clear_ntlm_auth_credentials.assert_called_once()
        clear_http_version.assert_called_once_with()
        http_conn_cls = pool_classes_by_scheme["http"].ConnectionCls
        https_conn_cls = pool_classes_by_scheme["https"].ConnectionCls
        assert http_conn_cls is HTTPConnection
        assert https_conn_cls is HTTPSConnection
