import unittest

import requests

import requests_ntlm2
from  requests_ntlm2 import HttpNtlmAdapter, HttpNtlmAuth


"""
This test is meant to run with Appveyor but until the integration is solved
it can only be run locally. The script setup_iis.ps1 can set up an IIS server
with the 4 scenarios tested below if you wish to run a sanity check
"""

username = ".\\User"
password = "Password01"
http_with_cbt = "http://127.0.0.1:81/contents.txt"
http_without_cbt = "http://127.0.0.1:82/contents.txt"
https_with_cbt = "https://127.0.0.1:441/contents.txt"
https_without_cbt = "https://127.0.0.1:442/contents.txt"
expected = "contents"


class Test_Functional:
    def test_ntlm_http_with_cbt(self):
        actual = send_request(http_with_cbt, username, password)
        actual_content = actual.content.decode("utf-8")
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == expected

    def test_ntlm_http_without_cbt(self):
        actual = send_request(http_without_cbt, username, password)
        actual_content = actual.content.decode("utf-8")
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == expected

    def test_ntlm_https_with_cbt(self):
        actual = send_request(https_with_cbt, username, password)
        actual_content = actual.content.decode("utf-8")
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == expected

    def test_ntlm_https_without_cbt(self):
        actual = send_request(https_without_cbt, username, password)
        actual_content = actual.content.decode("utf-8")
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == expected


class TestLocalNtlmProxy(unittest.TestCase):
    def test_http_connect(self):
        proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http:127.0.0.1:8080"
        }
        username = "testusser"
        password = "Test123"
        auth = HttpNtlmAuth(username, password)

        session = requests.Session()
        session.auth = auth
        session.proxies = proxies
        session.mount("http://", HttpNtlmAdapter(username, password))
        session.mount("https://", HttpNtlmAdapter(username, password))

        response = session.get("https://www.github.com:443", verify="proxy-ntlm-cert.crt")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.url, "bla", response.url)


def send_request(url, username, password):
    """
    Sends a request to the url with the credentials specified.

    Returns the final response
    """
    session = requests.Session()
    session.verify = False
    session.auth = requests_ntlm2.HttpNtlmAuth(username, password)
    response = session.get(url)

    return response
