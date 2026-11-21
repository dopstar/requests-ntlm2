from typing import TYPE_CHECKING, Any, Optional

from ...compatibility import NtlmCompatibility
from ..connection import DEFAULT_HTTP_VERSION
from ..connection import HTTPConnection as _HTTPConnection
from ..connection import HTTPSConnection as _HTTPSConnection
from .base import HttpProxyAdapter


if TYPE_CHECKING:
    from urllib3.connection import HTTPConnection, HTTPSConnection
    from urllib3.poolmanager import pool_classes_by_scheme
else:
    from requests.packages.urllib3.connection import HTTPConnection, HTTPSConnection
    from requests.packages.urllib3.poolmanager import pool_classes_by_scheme


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
        self._setup(
            ntlm_username,
            ntlm_password,
            ntlm_compatibility,
            ntlm_strict_mode,
            proxy_tunnelling_http_version
        )
        super().__init__(*args, **kwargs)

    def close(self) -> None:
        self._teardown()
        super().close()

    @staticmethod
    def _setup(
        username: str,
        password: str,
        ntlm_compatibility: int,
        ntlm_strict_mode: bool,
        http_version: Optional[str],
    ) -> None:
        pool_classes_by_scheme["http"].ConnectionCls = _HTTPConnection
        pool_classes_by_scheme["https"].ConnectionCls = _HTTPSConnection
        _HTTPSConnection.set_ntlm_auth_credentials(username, password)

        if http_version:
            _HTTPSConnection.set_http_version(http_version)

        _HTTPSConnection.ntlm_compatibility = ntlm_compatibility
        _HTTPConnection.ntlm_strict_mode = ntlm_strict_mode

    @staticmethod
    def _teardown() -> None:
        pool_classes_by_scheme["http"].ConnectionCls = HTTPConnection
        pool_classes_by_scheme["https"].ConnectionCls = HTTPSConnection
        _HTTPSConnection.clear_ntlm_auth_credentials()
        _HTTPSConnection.clear_http_version()
