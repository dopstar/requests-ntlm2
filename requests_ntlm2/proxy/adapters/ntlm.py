from typing import TYPE_CHECKING, Any, Optional

from ...compatibility import NtlmCompatibility
from ..connection import DEFAULT_HTTP_VERSION, VerifiedHTTPSConnection
from .base import HttpProxyAdapter


if TYPE_CHECKING:
    from urllib3.connectionpool import HTTPSConnectionPool
else:
    from requests.packages.urllib3.connectionpool import HTTPSConnectionPool


class HttpNtlmAdapter(HttpProxyAdapter):
    def __init__(
        self,
        ntlm_username: str,
        ntlm_password: str,
        ntlm_compatibility: int = NtlmCompatibility.NTLMv2_DEFAULT,
        ntlm_strict_mode: bool = False,
        proxy_tunnelling_http_version: Optional[str] = DEFAULT_HTTP_VERSION,
        *args: Any,
        **kwargs: Any
    ) -> None:
        """
        Thin wrapper around requests.adapters.HTTPAdapter
        """
        class NtlmHTTPSConnection(VerifiedHTTPSConnection):
            pass

        NtlmHTTPSConnection.set_ntlm_auth_credentials(ntlm_username, ntlm_password)
        NtlmHTTPSConnection.ntlm_compatibility = ntlm_compatibility
        NtlmHTTPSConnection.ntlm_strict_mode = ntlm_strict_mode
        if proxy_tunnelling_http_version:
            NtlmHTTPSConnection.set_http_version(proxy_tunnelling_http_version)

        class NtlmHTTPSConnectionPool(HTTPSConnectionPool):
            ConnectionCls = NtlmHTTPSConnection  # pyright: ignore[reportAssignmentType]

        self._ntlm_pool_class = NtlmHTTPSConnectionPool
        super().__init__(*args, **kwargs)

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        manager = super().proxy_manager_for(proxy, **proxy_kwargs)
        pool_classes = manager.pool_classes_by_scheme
        if pool_classes["https"] is HTTPSConnectionPool:
            # Copy the mapping so neither the defaults nor other adapters are affected.
            manager.pool_classes_by_scheme = dict(pool_classes, https=self._ntlm_pool_class)
        return manager
