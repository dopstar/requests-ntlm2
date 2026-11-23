"""Host and User-Agent header handling for Requests proxy adapters."""

import logging
from typing import Any, Dict, Optional, cast
from urllib.parse import urlparse

from requests import PreparedRequest
from requests.adapters import HTTPAdapter


logger = logging.getLogger(__name__)


class HttpProxyAdapter(HTTPAdapter):
    """Normalize destination Host headers and provide a proxy User-Agent fallback."""
    def __init__(
        self, user_agent: Optional[str] = None, *args: Any, **kwargs: Any
    ) -> None:
        """Configure an optional proxy User-Agent and forward pool options to Requests."""
        self._user_agent = user_agent
        super().__init__(*args, **kwargs)

    def _add_host_header(self, request: PreparedRequest) -> None:
        if request.headers.get("Host"):
            if self._is_valid_host_header(request):
                return
            else:
                self._remove_host_header(request)

        parse_result = urlparse(cast(str, request.url))
        if parse_result.scheme == "http":
            if parse_result.port == 80:
                request.headers["Host"] = cast(str, parse_result.hostname)
            else:
                request.headers["Host"] = parse_result.netloc

    @staticmethod
    def _is_valid_host_header(request: PreparedRequest) -> bool:
        host = request.headers.get("Host")
        if not host:
            return False
        parse_result = urlparse(cast(str, request.url))
        if parse_result.scheme == "https":
            if host == parse_result.netloc and parse_result.port is not None:
                return True
        return False

    @staticmethod
    def _remove_host_header(request: PreparedRequest) -> None:
        try:
            del request.headers["Host"]
        except KeyError:
            pass

    def add_headers(self, request: PreparedRequest, **kwargs: Any) -> None:
        """Apply Requests' adapter headers and normalize the destination Host header."""
        super().add_headers(request, **kwargs)
        self._add_host_header(request)

    def proxy_headers(self, proxy: str) -> Dict[str, str]:
        """Return proxy headers, adding the configured User-Agent when one is absent."""
        headers = super().proxy_headers(proxy)
        if self._user_agent and all(k.lower() != "user-agent" for k in headers):
            headers["User-Agent"] = self._user_agent
        logger.debug("proxy headers: %s", headers)
        return headers
