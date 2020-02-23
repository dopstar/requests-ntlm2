import logging
import re
import socket

from requests.packages.urllib3.connection import DummyConnection
from requests.packages.urllib3.connection import HTTPConnection as _HTTPConnection
from requests.packages.urllib3.connection import HTTPSConnection as _HTTPSConnection
from requests.packages.urllib3.connection import VerifiedHTTPSConnection as _VerifiedHTTPSConnection
from requests.packages.urllib3.packages.six.moves.http_client import (
    PROXY_AUTHENTICATION_REQUIRED,
    LineTooLong
)

from .core import NtlmCompatibility, get_ntlm_credentials
from .dance import HttpNtlmContext


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


class HTTPConnection(_HTTPConnection):
    pass


class HTTPSConnection(_HTTPSConnection):
    pass


class VerifiedHTTPSConnection(_VerifiedHTTPSConnection):
    ntlm_compatibility = NtlmCompatibility.NTLMv2_DEFAULT

    def __init__(self, *args, **kwargs):
        super(VerifiedHTTPSConnection, self).__init__(*args, **kwargs)
        self.__continue_reading_headers = True
        if self.ntlm_compatibility is None:
            self.ntlm_compatibility = NtlmCompatibility.NTLMv2_DEFAULT

    @classmethod
    def set_ntlm_auth_credentials(cls, username, password):
        cls._ntlm_credentials = get_ntlm_credentials(username, password)

    @classmethod
    def clear_ntlm_auth_credentials(cls):
        cls._ntlm_credentials = None
        del cls._ntlm_credentials

    def handle_http09_response(self, response):
        status_line_regex = re.compile(
            r"(?P<version>HTTP/\d\.\d)\s+(?P<status>\d+)\s+(?P<message>.+)",
            re.DOTALL
        )

        status_line = None
        while True:
            line = response.fp.readline()
            if not line.strip():
                self.__continue_reading_headers = False
                break
            match = status_line_regex.search(line)
            if match:
                status_line = match.groupdict()
                logger.debug("< %r", "{version} {status} {message}".format(**status_line))
            for header in _TRACKED_HEADERS:
                if line.lower().startswith("{}:".format(header)):
                    logger.info("< %r", line)
        if status_line:
            return status_line["version"], int(status_line["status"]), status_line["message"]
        return None

    def _get_response(self):
        response = self.response_class(self.sock, method=self._method)
        version, code, message = response._read_status()

        if (version, code, message) in _ASSUMED_HTTP09_STATUS_LINES:
            logger.warning("server response used outdated HTTP version: HTTP/0.9")
            status_line = self.handle_http09_response(response)
            if status_line:
                old_status_line = version, code, message
                version, code, message = status_line
                logger.info("changed status line from %s, to %s", old_status_line, status_line)
        else:
            logger.debug("< %r", "{} {} {}".format(version, code, message))
        return version, code, message, response

    def _get_header_bytes(self, proxy_auth_header=None):
        host, port = self._get_hostport(self._tunnel_host, self._tunnel_port)
        http_connect_string = "CONNECT {}:{} HTTP/1.0\r\n".format(host, port)
        logger.debug("> %r", http_connect_string)
        header_bytes = http_connect_string
        if proxy_auth_header:
            self._tunnel_headers["Proxy-Authorization"] = proxy_auth_header
        self._tunnel_headers["Proxy-Connection"] = "Keep-Alive"
        self._tunnel_headers["Host"] = "{}:{}".format(host, port)

        for header in sorted(self._tunnel_headers):
            value = self._tunnel_headers[header]
            header_byte = "%s: %s\r\n" % (header, value)
            logger.debug("> %r", header_byte)
            header_bytes += header_byte
        header_bytes += "\r\n"
        return header_bytes.encode("latin1")

    def _tunnel(self):
        username, password, domain = self._ntlm_credentials
        logger.debug("attempting to open tunnel using HTTP CONNECT")
        logger.debug("username: %s, domain: %s", username, domain)

        ntlm_context = HttpNtlmContext(
            username,
            password,
            domain=domain,
            auth_type="NTLM",
            ntlm_compatibility=self.ntlm_compatibility
        )

        negotiate_header = ntlm_context.get_negotiate_header()
        header_bytes = self._get_header_bytes(proxy_auth_header=negotiate_header)
        self.send(header_bytes)
        version, code, message, response = self._get_response()

        if code == PROXY_AUTHENTICATION_REQUIRED:
            authenticate_hdr = None
            match_string = "Proxy-Authenticate: NTLM "
            while True:
                line = response.fp.readline()
                if line.decode("utf-8").startswith(match_string):
                    logger.debug("< %r", line)
                    line = line.decode("utf-8")
                    ntlm_context.set_challenge_from_header(line)
                    authenticate_hdr = ntlm_context.get_authenticate_header()
                    continue

                if len(line) > _MAXLINE:
                    raise LineTooLong("header line")
                if not line:
                    # for sites which EOF without sending a trailer
                    break
                if line in (b"\r\n", b"\n", b""):
                    break

                for header in _TRACKED_HEADERS:
                    if line.decode("utf-8").lower().startswith("{}:".format(header)):
                        logger.info("< %r", line)

            header_bytes = self._get_header_bytes(proxy_auth_header=authenticate_hdr)
            self.send(header_bytes)
            version, code, message, response = self._get_response()

        if code != 200:
            self.close()
            raise socket.error(
                "Tunnel connection failed: %d %s" % (code, message.strip())
            )
        while self.__continue_reading_headers:
            line = response.fp.readline()
            if len(line) > _MAXLINE:
                raise LineTooLong("header line")
            if not line:
                # for sites which EOF without sending trailer
                break
            if line == b"\r\n":
                break


try:
    import ssl  # noqa

    # Make a copy for testing.
    UnverifiedHTTPSConnection = HTTPSConnection
    HTTPSConnection = VerifiedHTTPSConnection
except ImportError:
    HTTPSConnection = DummyConnection
