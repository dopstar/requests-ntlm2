import logging
import re
import select
import socket
from http.client import PROXY_AUTHENTICATION_REQUIRED, HTTPResponse, LineTooLong
from typing import TYPE_CHECKING, Any, ClassVar, Dict, Optional, Tuple, Union, cast

from ..compatibility import NtlmCompatibility
from ..dance import HttpNtlmContext, get_ntlm_credentials


if TYPE_CHECKING:
    from urllib3.connection import DummyConnection
    from urllib3.connection import HTTPConnection as _HTTPConnection
    from urllib3.connection import HTTPSConnection as _HTTPSConnection
    from urllib3.connection import VerifiedHTTPSConnection as _VerifiedHTTPSConnection
else:
    from requests.packages.urllib3.connection import DummyConnection
    from requests.packages.urllib3.connection import HTTPConnection as _HTTPConnection
    from requests.packages.urllib3.connection import HTTPSConnection as _HTTPSConnection
    from requests.packages.urllib3.connection import (
        VerifiedHTTPSConnection as _VerifiedHTTPSConnection,
    )


IO_WAIT_TIMEOUT = 0.1


logger = logging.getLogger(__name__)

# maximal line length when calling readline().
_MAXLINE = 65536

_ASSUMED_HTTP09_STATUS_LINES = (
    ("HTTP/0.9", 200, ""),
    ("HTTP/0.9", 200, "OK"),
)

_TRACKED_HEADERS = (
    "proxy-authenticate",
    "proxy-support",
    "cache-control",
    "date",
    "server",
    "proxy-connection",
    "connection",
    "content-length",
    "content-type",
)

HTTP_VERSION_11 = "HTTP/1.1"
HTTP_VERSION_10 = "HTTP/1.0"
DEFAULT_HTTP_VERSION = HTTP_VERSION_10


class HTTPConnection(_HTTPConnection):
    ntlm_strict_mode: ClassVar[bool]


class VerifiedHTTPSConnection(_VerifiedHTTPSConnection):
    if TYPE_CHECKING:
        # Private http.client members used by the CONNECT handshake.
        _method: Optional[str]
        _tunnel_headers: Dict[str, str]

        def _get_hostport(
            self, host: Optional[str], port: Optional[int]
        ) -> Tuple[str, int]: ...

    _ntlm_credentials: ClassVar[Optional[Tuple[str, str, str]]]
    _http_version: ClassVar[Optional[str]]
    ntlm_compatibility = NtlmCompatibility.NTLMv2_DEFAULT
    ntlm_strict_mode = False

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._continue_reading_headers = True
        if self.ntlm_compatibility is None:
            self.ntlm_compatibility = NtlmCompatibility.NTLMv2_DEFAULT

    @classmethod
    def set_ntlm_auth_credentials(cls, username: str, password: str) -> None:
        cls._ntlm_credentials = get_ntlm_credentials(username, password)

    @classmethod
    def set_http_version(cls, http_version: str) -> None:
        if http_version in (HTTP_VERSION_10, HTTP_VERSION_11):
            cls._http_version = http_version
        else:
            logger.debug(
                "unsupported http-version %r, setting the default %r",
                http_version,
                DEFAULT_HTTP_VERSION
            )
            cls._http_version = DEFAULT_HTTP_VERSION

    @classmethod
    def clear_http_version(cls) -> None:
        cls._http_version = None
        del cls._http_version

    @classmethod
    def clear_ntlm_auth_credentials(cls) -> None:
        cls._ntlm_credentials = None
        del cls._ntlm_credentials

    @staticmethod
    def _is_line_blank(line: Optional[bytes]) -> bool:
        # for sites which EOF without sending a trailer
        if not line or line in (b"\r\n", b"\n", b"") or not line.strip():
            return True
        return False

    @staticmethod
    def _read_response_line_if_ready(response: HTTPResponse) -> Optional[bytes]:
        (ready, _, _) = select.select([response.fp], (), (), IO_WAIT_TIMEOUT)
        if ready:
            return response.fp.readline()
        return None

    def _flush_response_buffer(self, response: HTTPResponse) -> None:
        line_count = 0
        while True:
            line_count += 1
            logger.debug("* reading line from response buffer")
            line = self._read_response_line_if_ready(response)
            logger.debug("< line %s: %r", line_count, line)
            if not line:
                logger.debug("* finished draining the socket")
                break

    def handle_http09_response(
        self, response: HTTPResponse
    ) -> Optional[Tuple[bytes, int, bytes]]:
        status_line_regex = re.compile(
            br"(?P<version>HTTP/\d\.\d)\s+(?P<status>\d+)\s+(?P<message>.+)",
            re.DOTALL
        )

        while True:
            line = response.fp.readline()
            if not line:
                self._continue_reading_headers = False
                break
            match = status_line_regex.search(line)
            if match:
                version, status, message = match.groups()
                logger.debug("< %r", f"{version} {status} {message}")
                return version, int(status), message
        return None

    def _get_response(
        self,
    ) -> Tuple[Union[str, bytes], int, Union[str, bytes], HTTPResponse]:
        response = self.response_class(self.sock, method=self._method)
        version, code, message = response._read_status()  # pyright: ignore[reportAttributeAccessIssue]

        if (version, code, message) in _ASSUMED_HTTP09_STATUS_LINES:
            logger.warning("server response used outdated HTTP version: HTTP/0.9")
            status_line = self.handle_http09_response(response)
            if status_line:
                old_status_line = version, code, message
                version, code, message = status_line
                logger.info("changed status line from %s, to %s", old_status_line, status_line)
            else:
                logger.warning("could not handle HTTP/0.9 server response")
                logger.debug("HTTP/0.9: version=%s", version)
                logger.debug("HTTP/0.9: code=%s", code)
                logger.debug("HTTP/0.9: message=%s", message)
        else:
            logger.debug("< %r", f"{version} {code} {message}")
        return version, code, message, response

    def _get_http_version(self) -> str:
        return getattr(self, "_http_version", None) or DEFAULT_HTTP_VERSION

    def _get_header_bytes(self, proxy_auth_header: Optional[str] = None) -> bytes:
        host, port = self._get_hostport(self._tunnel_host, self._tunnel_port)
        http_connect_string = f"CONNECT {host}:{port} {self._get_http_version()}\r\n"
        logger.debug("> %r", http_connect_string)
        header_bytes = http_connect_string
        if proxy_auth_header:
            self._tunnel_headers["Proxy-Authorization"] = proxy_auth_header
        self._tunnel_headers["Proxy-Connection"] = "Keep-Alive"
        self._tunnel_headers["Host"] = f"{host}:{port}"

        for header in sorted(self._tunnel_headers):
            value = self._tunnel_headers[header]
            header_byte = f"{header}: {value}\r\n"
            logger.debug("> %r", header_byte)
            header_bytes += header_byte
        header_bytes += "\r\n"
        return header_bytes.encode("latin1")

    def _tunnel(self) -> None:
        username, password, domain = cast(Tuple[str, str, str], self._ntlm_credentials)
        logger.debug("* attempting to open tunnel using HTTP CONNECT")
        logger.debug("* username=%r, domain=%r", username, domain)

        try:
            workstation = socket.gethostname().upper()
        except (AttributeError, TypeError, ValueError):
            workstation = None

        logger.debug("* workstation=%r", workstation)

        ntlm_context = HttpNtlmContext(
            username,
            password,
            domain=domain,
            workstation=workstation,
            auth_type="NTLM",
            ntlm_compatibility=self.ntlm_compatibility,
            ntlm_strict_mode=self.ntlm_strict_mode
        )

        negotiate_header = ntlm_context.get_negotiate_header()
        header_bytes = self._get_header_bytes(proxy_auth_header=negotiate_header)
        logger.debug("* sending the NEGOTIATE message")
        self.send(header_bytes)
        version, code, message, response = self._get_response()

        if code == PROXY_AUTHENTICATION_REQUIRED:
            authenticate_hdr = None
            match_string = "Proxy-Authenticate: NTLM "
            last_line_is_blank = False
            line_count = 1
            while True:
                line_count += 1
                logger.debug("* reading line number %s", line_count)
                if last_line_is_blank:
                    line = self._read_response_line_if_ready(response)
                else:
                    line = response.fp.readline()
                logger.debug("* read line: %r", line)
                this_line_is_blank = self._is_line_blank(line)
                if last_line_is_blank and this_line_is_blank:
                    self._flush_response_buffer(response)
                    break

                if this_line_is_blank:
                    last_line_is_blank = True
                    continue
                else:
                    last_line_is_blank = False

                if line is not None and line.decode("utf-8").startswith(match_string):
                    logger.debug("< %r", line)
                    ntlm_context.set_challenge_from_header(line.decode("utf-8"))
                    authenticate_hdr = ntlm_context.get_authenticate_header()
                    self._flush_response_buffer(response)
                    break

                if line is not None and len(line) > _MAXLINE:
                    raise LineTooLong("header line")

                logger.debug("< %r", line)

            if not authenticate_hdr:
                logger.warning("* the NTLM challenge header was not found!")
            header_bytes = self._get_header_bytes(proxy_auth_header=authenticate_hdr)
            logger.debug("* sending the NTLM authenticate message")
            self.send(header_bytes)
            version, code, message, response = self._get_response()

        if code != 200:
            logger.error("* HTTP %s: failed to establish NTLM proxy tunnel", code)
            self.close()
            raise OSError(f"Tunnel connection failed: {code:d} {message.strip()}")
        while self._continue_reading_headers:
            line = response.fp.readline()
            if line is not None and len(line) > _MAXLINE:
                raise LineTooLong("header line")
            if line is None or self._is_line_blank(line):
                break

        logger.debug("* successfully established proxy tunnel!")


if TYPE_CHECKING:
    HTTPSConnection = VerifiedHTTPSConnection
else:
    class HTTPSConnection(_HTTPSConnection):
        pass


    try:
        import ssl  # noqa

        # Make a copy for testing.
        UnverifiedHTTPSConnection = HTTPSConnection
        HTTPSConnection = VerifiedHTTPSConnection
    except ImportError:
        HTTPSConnection = DummyConnection
