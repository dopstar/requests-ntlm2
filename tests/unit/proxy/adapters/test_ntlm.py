from types import SimpleNamespace
from unittest import mock

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.connectionpool import HTTPSConnectionPool

from requests_ntlm2.compatibility import NtlmCompatibility
from requests_ntlm2.proxy.adapters.base import HttpProxyAdapter
from requests_ntlm2.proxy.adapters.ntlm import HttpNtlmAdapter
from requests_ntlm2.proxy.connection import VerifiedHTTPSConnection


PROXY_URL = "http://proxy.example:8080"
TARGET_URL = "https://example.test"


class TestHttpNtlmAdapter:
    def test_proxy_pools_are_isolated(self):
        first = HttpNtlmAdapter(
            "FIRST\\alice",
            "password1",
            ntlm_compatibility=NtlmCompatibility.NTLMv1_WITH_ESS,
            ntlm_strict_mode=True,
            proxy_tunnelling_http_version="HTTP/1.1",
        )
        second = HttpNtlmAdapter("SECOND\\bob", "password2", proxy_tunnelling_http_version=None)

        try:
            assert isinstance(first, HttpProxyAdapter)
            first_manager = first.proxy_manager_for(PROXY_URL)
            assert first.proxy_manager_for(PROXY_URL) is first_manager
            second_manager = second.proxy_manager_for(PROXY_URL)

            first_cls = first_manager.connection_from_url(TARGET_URL).ConnectionCls
            second_cls = second_manager.connection_from_url(TARGET_URL).ConnectionCls
            assert issubclass(first_cls, VerifiedHTTPSConnection)
            assert first_cls is not second_cls
            assert first_cls._ntlm_credentials == ("alice", "password1", "FIRST")
            assert second_cls._ntlm_credentials == ("bob", "password2", "SECOND")
            assert first_cls.ntlm_compatibility == NtlmCompatibility.NTLMv1_WITH_ESS
            assert second_cls.ntlm_compatibility == NtlmCompatibility.NTLMv2_DEFAULT
            assert first_cls.ntlm_strict_mode is True
            assert second_cls.ntlm_strict_mode is False
            assert first_cls("example.test")._get_http_version() == "HTTP/1.1"
            assert second_cls("example.test")._get_http_version() == "HTTP/1.0"
        finally:
            first.close()
            second.close()

    def test_regular_connections_and_other_adapters_keep_their_pools(self):
        ntlm_adapter = HttpNtlmAdapter("alice", "password")
        default_adapter = HTTPAdapter()
        try:
            assert ntlm_adapter.poolmanager.connection_from_url(
                TARGET_URL
            ).__class__ is HTTPSConnectionPool
            assert default_adapter.proxy_manager_for(PROXY_URL).connection_from_url(
                TARGET_URL
            ).__class__ is HTTPSConnectionPool
        finally:
            ntlm_adapter.close()
            default_adapter.close()

    def test_closing_an_adapter_does_not_reset_another_adapters_credentials(self):
        first = HttpNtlmAdapter("alice", "password1")
        second = HttpNtlmAdapter("bob", "password2")
        try:
            first.proxy_manager_for(PROXY_URL)
            manager = second.proxy_manager_for(PROXY_URL)
            first.close()
            assert manager.connection_from_url(
                TARGET_URL
            ).ConnectionCls._ntlm_credentials == ("bob", "password2", "")
        finally:
            second.close()

    def test_specialized_proxy_pool_is_preserved(self):
        custom_pool = type("CustomPool", (HTTPSConnectionPool,), {})
        manager = SimpleNamespace(pool_classes_by_scheme={"https": custom_pool})
        adapter = HttpNtlmAdapter("alice", "password")
        try:
            with mock.patch.object(HTTPAdapter, "proxy_manager_for", return_value=manager):
                assert adapter.proxy_manager_for("socks5://proxy.example:1080") is manager
            assert manager.pool_classes_by_scheme["https"] is custom_pool
        finally:
            adapter.close()
