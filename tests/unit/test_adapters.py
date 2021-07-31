import mock
import requests.adapters
import requests.sessions
from requests.packages.urllib3.connection import HTTPConnection, HTTPSConnection

import requests_ntlm2.adapters
import requests_ntlm2.connection


class TestHttpProxyAdapter(object):
    def test_init(self):
        adapter = requests_ntlm2.adapters.HttpProxyAdapter()
        assert isinstance(adapter, requests_ntlm2.adapters.HttpProxyAdapter)
        assert isinstance(adapter, requests.adapters.HTTPAdapter)

    def test__add_host_header(self):
        adapter = requests_ntlm2.adapters.HttpProxyAdapter()
        request = requests.Request(url="http://github.com:80")
        assert request.headers.get("Host") is None

        adapter._add_host_header(request)
        assert request.headers.get("Host") is not None
        assert request.headers["Host"] == "github.com"

        request = requests.Request(url="https://github.com:443")
        assert request.headers.get("Host") is None
        adapter._add_host_header(request)
        assert request.headers.get("Host") is None

    def test__add_host_header__already_added(self):
        adapter = requests_ntlm2.adapters.HttpProxyAdapter()
        request = requests.Request(url="http://github.com:80")
        request.headers["Host"] = "github.com:123"
        adapter._add_host_header(request)
        assert request.headers.get("Host") == "github.com"

        request = requests.Request(url="http://github.com:8080")
        request.headers["Host"] = "github.com:123"
        adapter._add_host_header(request)
        assert request.headers.get("Host") == "github.com:8080"

        request = requests.Request(url="https://github.com:8080")
        request.headers["Host"] = "github.com:123"
        adapter._add_host_header(request)
        assert request.headers.get("Host") is None

        request = requests.Request(url="https://github.com:8080")
        request.headers["Host"] = "github.com:8080"
        adapter._add_host_header(request)
        assert request.headers.get("Host") == "github.com:8080"

    def test__is_valid_host_header(self):
        adapter = requests_ntlm2.adapters.HttpProxyAdapter()
        request = requests.Request()
        assert adapter._is_valid_host_header(request) is False

        request.url = "https://google.com:443"
        request.headers["Host"] = "google.com:443"
        assert adapter._is_valid_host_header(request) is True

        request.url = "https://google.com:8080"
        assert adapter._is_valid_host_header(request) is False

    def test__remove_host_header(self):
        adapter = requests_ntlm2.adapters.HttpProxyAdapter()
        request = requests.Request()
        assert adapter._remove_host_header(request) is None
        assert request.headers.get("Host") is None

        request.headers["Host"] = "google.com:443"
        assert adapter._remove_host_header(request) is None
        assert request.headers.get("Host") is None

    @mock.patch("requests_ntlm2.adapters.HttpProxyAdapter._add_host_header")
    def test_add_headers(self, mock_add_host_header):
        adapter = requests_ntlm2.adapters.HttpProxyAdapter()
        request = requests.Request(url="http://github.com:80")
        assert adapter.add_headers(request) is None
        mock_add_host_header.assert_called_once_with(request)

    @mock.patch("requests.adapters.HTTPAdapter.proxy_headers", return_value={'foo': 'bar'})
    def test_add_headers(self, mock_proxy_headers):
        adapter = requests_ntlm2.adapters.HttpProxyAdapter()
        request = requests.Request(url="http://github.com:80")
        assert adapter.proxy_headers({}) == {"foo": "bar"}
        mock_proxy_headers.assert_called_once_with({})

    @mock.patch("requests.adapters.HTTPAdapter.proxy_headers", return_value={'foo': 'bar'})
    def test_add_headers__with_user_agent(self, mock_proxy_headers):
        adapter = requests_ntlm2.adapters.HttpProxyAdapter(user_agent='fake-ua/1.0')
        request = requests.Request(url="http://github.com:80")
        assert adapter.proxy_headers({"this": "that"}) == {
            "foo": "bar",
            "User-Agent": "fake-ua/1.0"
        }
        mock_proxy_headers.assert_called_once_with({"this": "that"})


class TestHttpNtlmAdapter(object):
    @mock.patch("requests_ntlm2.adapters.HttpNtlmAdapter._teardown")
    @mock.patch("requests_ntlm2.adapters.HttpNtlmAdapter._setup")
    def test_init(self, mock_setup, mock_teardown):
        adapter = requests_ntlm2.adapters.HttpNtlmAdapter("username", "password")
        assert isinstance(adapter, requests_ntlm2.adapters.HttpNtlmAdapter)
        assert isinstance(adapter, requests_ntlm2.adapters.HttpProxyAdapter)
        assert isinstance(adapter, requests.adapters.HTTPAdapter)
        mock_setup.assert_called_once_with("username", "password", 3, False)
        mock_teardown.assert_not_called()

    @mock.patch("requests_ntlm2.adapters.HttpNtlmAdapter._teardown")
    @mock.patch("requests_ntlm2.adapters.HttpNtlmAdapter._setup")
    def test_init__strict_mode(self, mock_setup, mock_teardown):
        adapter = requests_ntlm2.adapters.HttpNtlmAdapter(
            "username",
            "password",
            ntlm_strict_mode=True
        )
        assert isinstance(adapter, requests_ntlm2.adapters.HttpNtlmAdapter)
        assert isinstance(adapter, requests_ntlm2.adapters.HttpProxyAdapter)
        assert isinstance(adapter, requests.adapters.HTTPAdapter)
        mock_setup.assert_called_once_with("username", "password", 3, True)
        mock_teardown.assert_not_called()

    @mock.patch("requests_ntlm2.adapters.HttpNtlmAdapter._teardown")
    @mock.patch("requests_ntlm2.adapters.HttpNtlmAdapter._setup")
    def close(self, mock_setup, mock_teardown):
        adapter = requests_ntlm2.adapters.HttpNtlmAdapter("username", "password")
        assert adapter.close() is None
        mock_setup.assert_called_once_with("username", "password", 3)
        mock_teardown.assert_called_once()

    @mock.patch("requests_ntlm2.connection.HTTPSConnection.set_ntlm_auth_credentials")
    def test__setup(self, mock_set_ntlm_auth_credentials):
        from requests.packages.urllib3.poolmanager import pool_classes_by_scheme
        adapter = requests_ntlm2.adapters.HttpNtlmAdapter("username", "password")
        mock_set_ntlm_auth_credentials.assert_called_once_with("username", "password")

        http_conn_cls = pool_classes_by_scheme["http"].ConnectionCls
        https_conn_cls = pool_classes_by_scheme["https"].ConnectionCls
        assert http_conn_cls is requests_ntlm2.connection.HTTPConnection
        assert https_conn_cls is requests_ntlm2.connection.HTTPSConnection
        adapter.close()

    @mock.patch("requests_ntlm2.connection.HTTPSConnection.clear_ntlm_auth_credentials")
    @mock.patch("requests_ntlm2.connection.HTTPSConnection.set_ntlm_auth_credentials")
    def test_close(self, set_ntlm_auth_credentials, clear_ntlm_auth_credentials):
        from requests.packages.urllib3.poolmanager import pool_classes_by_scheme
        adapter = requests_ntlm2.adapters.HttpNtlmAdapter("username2", "password")
        set_ntlm_auth_credentials.assert_called_once_with("username2", "password")

        http_conn_cls = pool_classes_by_scheme["http"].ConnectionCls
        https_conn_cls = pool_classes_by_scheme["https"].ConnectionCls
        assert http_conn_cls is requests_ntlm2.connection.HTTPConnection
        assert https_conn_cls is requests_ntlm2.connection.HTTPSConnection

        adapter.close()
        clear_ntlm_auth_credentials.assert_called_once()
        http_conn_cls = pool_classes_by_scheme["http"].ConnectionCls
        https_conn_cls = pool_classes_by_scheme["https"].ConnectionCls
        assert http_conn_cls is HTTPConnection
        assert https_conn_cls is HTTPSConnection
