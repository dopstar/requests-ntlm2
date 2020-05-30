try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.connection import HTTPConnection, HTTPSConnection
from requests.packages.urllib3.poolmanager import pool_classes_by_scheme

from .connection import HTTPConnection as _HTTPConnection
from .connection import HTTPSConnection as _HTTPSConnection
from .core import NtlmCompatibility


class HttpProxyAdapter(HTTPAdapter):
    def _add_host_header(self, request):
        if request.headers.get("Host"):
            if self._is_valid_host_header(request):
                return
            else:
                self._remove_host_header(request)

        parse_result = urlparse.urlparse(request.url)
        if parse_result.scheme == "http":
            if parse_result.port == 80:
                request.headers["Host"] = parse_result.hostname
            else:
                request.headers["Host"] = parse_result.netloc

    @staticmethod
    def _is_valid_host_header(request):
        host = request.headers.get("Host")
        if not host:
            return False
        parse_result = urlparse.urlparse(request.url)
        if parse_result.scheme == "https":
            if host == parse_result.netloc and parse_result.port is not None:
                return True
        return False

    @staticmethod
    def _remove_host_header(request):
        try:
            del request.headers["Host"]
        except KeyError:
            pass

    def add_headers(self, request, **kwargs):
        super(HttpProxyAdapter, self).add_headers(request, **kwargs)
        self._add_host_header(request)


class HttpNtlmAdapter(HttpProxyAdapter):
    def __init__(
        self,
        ntlm_username,
        ntlm_password,
        ntlm_compatibility=NtlmCompatibility.NTLMv2_DEFAULT,
        ntlm_strict_mode=False,
        *args,
        **kwargs
    ):
        """
        Thin wrapper around requests.adapters.HTTPAdapter
        """
        self._setup(ntlm_username, ntlm_password, ntlm_compatibility, ntlm_strict_mode)
        super(HttpNtlmAdapter, self).__init__(*args, **kwargs)

    def close(self):
        self._teardown()
        super(HttpNtlmAdapter, self).close()

    @staticmethod
    def _setup(username, password, ntlm_compatibility, ntlm_strict_mode):
        pool_classes_by_scheme["http"].ConnectionCls = _HTTPConnection
        pool_classes_by_scheme["https"].ConnectionCls = _HTTPSConnection
        _HTTPSConnection.set_ntlm_auth_credentials(username, password)
        _HTTPSConnection.ntlm_compatibility = ntlm_compatibility
        _HTTPConnection.ntlm_strict_mode = ntlm_strict_mode

    @staticmethod
    def _teardown():
        pool_classes_by_scheme["http"].ConnectionCls = HTTPConnection
        pool_classes_by_scheme["https"].ConnectionCls = HTTPSConnection
        _HTTPSConnection.clear_ntlm_auth_credentials()
