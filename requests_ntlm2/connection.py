import socket

from requests.packages.urllib3.connection import DummyConnection
from requests.packages.urllib3.connection import HTTPConnection as _HTTPConnection
from requests.packages.urllib3.connection import HTTPSConnection as _HTTPSConnection
from requests.packages.urllib3.connection import VerifiedHTTPSConnection as _VerifiedHTTPSConnection
from requests.packages.urllib3.packages.six.moves.http_client import (
    PROXY_AUTHENTICATION_REQUIRED,
    LineTooLong
)

from .core import get_ntlm_credentials
from .dance import HttpNtlmContext


# maximal line length when calling readline().
_MAXLINE = 65536


class HTTPConnection(_HTTPConnection):
    pass


class HTTPSConnection(_HTTPSConnection):
    pass


class VerifiedHTTPSConnection(_VerifiedHTTPSConnection):
    @classmethod
    def set_ntlm_auth_credentials(cls, username, password):
        cls._ntlm_credentials = get_ntlm_credentials(username, password)

    @classmethod
    def clear_ntlm_auth_credentials(cls):
        cls._ntlm_credentials = None
        del cls._ntlm_credentials

    def _get_response(self):
        response = self.response_class(self.sock, method=self._method)
        version, code, message = response._read_status()
        return version, code, message, response

    def _get_header_bytes(self, proxy_auth_header=None):
        host, port = self._get_hostport(self._tunnel_host, self._tunnel_port)
        http_connect_string = b"CONNECT {}:{} HTTP/1.0\r\n".format(host, port)
        header_bytes = http_connect_string
        if proxy_auth_header:
            self._tunnel_headers["Proxy-Authorization"] = proxy_auth_header
        self._tunnel_headers["Proxy-Connection"] = "Keep-Alive"
        self._tunnel_headers["Host"] = "{}:{}".format(host, port)

        for header, value in self._tunnel_headers.items():
            header_str = "%s: %s\r\n" % (header, value)
            header_bytes += header_str.encode("latin-1")
        header_bytes += b"\r\n"
        return header_bytes

    def _tunnel(self):
        username, password, domain = self._ntlm_credentials

        ntlm_context = HttpNtlmContext(
            username, password, domain=domain, auth_type="NTLM"
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
                    line = line.decode("utf-8")
                    ntlm_context.set_challenge_from_header(line)
                    authenticate_hdr = ntlm_context.get_authenticate_header()

                if len(line) > _MAXLINE:
                    raise LineTooLong("header line")
                if not line:
                    # for sites which EOF without sending a trailer
                    break
                if line in (b"\r\n", b"\n", b""):
                    break

            header_bytes = self._get_header_bytes(proxy_auth_header=authenticate_hdr)
            self.send(header_bytes)
            version, code, message, response = self._get_response()

        if code != 200:
            self.close()
            raise socket.error(
                "Tunnel connection failed: %d %s" % (code, message.strip())
            )
        while True:
            line = response.fp.readline()
            if len(line) > _MAXLINE:
                raise LineTooLong("header line")
            if not line:
                # for sites which EOF without sending trailer
                break
            if line == "\r\n":
                break


try:
    import ssl  # noqa

    # Make a copy for testing.
    UnverifiedHTTPSConnection = HTTPSConnection
    HTTPSConnection = VerifiedHTTPSConnection
except ImportError:
    HTTPSConnection = DummyConnection
