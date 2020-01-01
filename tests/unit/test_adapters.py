import unittest
import mock

import requests.adapters
import requests.sessions

import requests_ntlm2.adapters


class TestHttpProxyAdapter(unittest.TestCase):
    def test_init(self):
        adapter = requests_ntlm2.adapters.HttpProxyAdapter()
        self.assertIsInstance(adapter, requests_ntlm2.adapters.HttpProxyAdapter)
        self.assertIsInstance(adapter, requests.adapters.HTTPAdapter)

    def test__add_host_header(self):
        adapter = requests_ntlm2.adapters.HttpProxyAdapter()
        request = requests.Request(url='http://github.com:80')
        self.assertIsNone(request.headers.get('Host'))

        adapter._add_host_header(request)
        self.assertIsNotNone(request.headers.get('Host'))
        self.assertEqual(request.headers['Host'], 'github.com')

        request = requests.Request(url='https://github.com:443')
        self.assertIsNone(request.headers.get('Host'))
        adapter._add_host_header(request)
        self.assertIsNone(request.headers.get('Host'))

    def test__is_valid_host_header(self):
        adapter = requests_ntlm2.adapters.HttpProxyAdapter()
        request = requests.Request()
        self.assertFalse(adapter._is_valid_host_header(request))

        request.url = 'https://google.com:443'
        request.headers['Host'] = 'google.com:443'
        self.assertTrue(adapter._is_valid_host_header(request))

        request.url = 'https://google.com:8080'
        self.assertFalse(adapter._is_valid_host_header(request))

    def test__remove_host_header(self):
        adapter = requests_ntlm2.adapters.HttpProxyAdapter()
        request = requests.Request()
        self.assertIsNone(adapter._remove_host_header(request))
        self.assertIsNone(request.headers.get('Host'))

        request.headers['Host'] = 'google.com:443'
        self.assertIsNone(adapter._remove_host_header(request))
        self.assertIsNone(request.headers.get('Host'))

    @mock.patch('requests_ntlm2.adapters.HttpProxyAdapter._add_host_header')
    def test_add_headers(self, mock_add_host_header):
        adapter = requests_ntlm2.adapters.HttpProxyAdapter()
        request = requests.Request(url='http://github.com:80')
        self.assertIsNone(adapter.add_headers(request))
        mock_add_host_header.assert_called_once_with(request)
