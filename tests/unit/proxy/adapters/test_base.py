from unittest import mock

import requests.adapters

from requests_ntlm2.proxy.adapters.base import HttpProxyAdapter


class TestHttpProxyAdapter:
    def test_init(self):
        adapter = HttpProxyAdapter()
        assert isinstance(adapter, HttpProxyAdapter)
        assert isinstance(adapter, requests.adapters.HTTPAdapter)

    def test__add_host_header(self):
        adapter = HttpProxyAdapter()
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
        adapter = HttpProxyAdapter()
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
        adapter = HttpProxyAdapter()
        request = requests.Request()
        assert adapter._is_valid_host_header(request) is False

        request.url = "https://google.com:443"
        request.headers["Host"] = "google.com:443"
        assert adapter._is_valid_host_header(request) is True

        request.url = "https://google.com:8080"
        assert adapter._is_valid_host_header(request) is False

    def test__remove_host_header(self):
        adapter = HttpProxyAdapter()
        request = requests.Request()
        assert adapter._remove_host_header(request) is None
        assert request.headers.get("Host") is None

        request.headers["Host"] = "google.com:443"
        assert adapter._remove_host_header(request) is None
        assert request.headers.get("Host") is None

    @mock.patch("requests_ntlm2.proxy.adapters.base.HttpProxyAdapter._add_host_header")
    def test_add_headers(self, mock_add_host_header):
        adapter = HttpProxyAdapter()
        request = requests.Request(url="http://github.com:80")
        assert adapter.add_headers(request) is None
        mock_add_host_header.assert_called_once_with(request)

    @mock.patch("requests.adapters.HTTPAdapter.proxy_headers", return_value={"foo": "bar"})
    def test_proxy_headers(self, mock_proxy_headers):
        adapter = HttpProxyAdapter()
        assert adapter.proxy_headers({}) == {"foo": "bar"}
        mock_proxy_headers.assert_called_once_with({})

    @mock.patch("requests.adapters.HTTPAdapter.proxy_headers", return_value={"foo": "bar"})
    def test_proxy_headers__with_user_agent(self, mock_proxy_headers):
        adapter = HttpProxyAdapter(user_agent="fake-ua/1.0")
        assert adapter.proxy_headers({"this": "that"}) == {
            "foo": "bar",
            "User-Agent": "fake-ua/1.0"
        }
        mock_proxy_headers.assert_called_once_with({"this": "that"})
