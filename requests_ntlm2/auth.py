import io
from collections.abc import Iterator
from typing import Any, BinaryIO, Dict, Optional, Tuple, cast
from urllib.request import parse_http_list

from ntlm_auth.session_security import SessionSecurity
from requests import PreparedRequest, Response
from requests.auth import AuthBase
from requests.exceptions import RequestException

from ._channel_binding import get_cbt_data
from .compatibility import NtlmCompatibility
from .dance import HttpNtlmContext, get_ntlm_credentials


def get_auth_type_from_header(header: str) -> Optional[str]:
    """
    Given a WWW-Authenticate or Proxy-Authenticate header, returns the
    authentication type to use. We prefer NTLM over Negotiate if the server
    supports it.
    """
    schemes = {
        challenge.split(None, 1)[0].lower()
        for challenge in parse_http_list(header)
        if challenge.strip()
    }
    if "ntlm" in schemes:
        return "NTLM"
    elif "negotiate" in schemes:
        return "Negotiate"
    return None


def _rewind_request_body(request: PreparedRequest) -> None:
    body = request.body
    if hasattr(body, "seek"):
        seek = cast(BinaryIO, body).seek
        position = getattr(request, "_body_position", None)
        if isinstance(position, int):
            seek(position)
            return

        # Older Requests versions may not save the body's starting position.
        content_length = int(request.headers.get("Content-Length", "0"))
        if content_length > 0:
            try:
                seek(-content_length, 1)
                return
            except (io.UnsupportedOperation, OSError, ValueError):
                pass
        seek(0)
    elif isinstance(body, Iterator) or hasattr(body, "read"):
        raise RequestException("Cannot resend a non-rewindable body for NTLM authentication")


class HttpNtlmAuth(AuthBase):
    """
    HTTP NTLM Authentication Handler for Requests.
    """

    def __init__(
        self,
        username: str,
        password: str,
        send_cbt: bool = True,
        ntlm_compatibility: int = NtlmCompatibility.NTLMv2_DEFAULT,
        ntlm_strict_mode: bool = False,
    ) -> None:
        """Create an authentication handler for NTLM over HTTP.

        :param str username: Username in 'domain\\username' format
        :param str password: Password
        :param bool send_cbt: Will send the channel bindings over a
                              HTTPS channel (Default: True)
        :param ntlm_compatibility: The Lan Manager Compatibility Level to use with the auth message
        :param ntlm_strict_mode: If False, tries to Type 2 (ie challenge response) NTLM message
                                that does not conform to the NTLM spec
        """

        self.username, self.password, self.domain = get_ntlm_credentials(username, password)

        if self.domain:
            self.domain = self.domain.upper()
        self.send_cbt = send_cbt
        self.ntlm_compatibility = ntlm_compatibility
        self.ntlm_strict_mode = ntlm_strict_mode

        # This exposes the encrypt/decrypt methods used to encrypt and decrypt
        # messages sent after ntlm authentication. These methods are utilised
        # by libraries that call requests_ntlm to encrypt and decrypt the
        # messages sent after authentication
        self.session_security: Optional[SessionSecurity] = None

    def retry_using_http_ntlm_auth(
        self,
        auth_header_field: str,
        auth_header: str,
        response: Response,
        auth_type: str,
        kwargs: Dict[str, Any],
    ) -> Response:
        if auth_header in response.request.headers:
            return response

        cbt_data = get_cbt_data(response) if self.send_cbt else None

        # Consume content and release the original connection
        # to allow our new request to reuse the same one.
        _ = response.content
        response.raw.release_conn()
        request = response.request.copy()

        ntlm_context = HttpNtlmContext(
            self.username,
            self.password,
            domain=self.domain,
            auth_type=auth_type,
            cbt_data=cbt_data,
            ntlm_compatibility=self.ntlm_compatibility,
            ntlm_strict_mode=self.ntlm_strict_mode
        )
        request.headers[auth_header] = ntlm_context.get_negotiate_header()

        # A streaming response breaks authentication.
        # This can be fixed by not streaming this request, which is safe
        # because the returned response3 will still have stream=True set if
        # specified in args. In addition, we expect this request to give us a
        # challenge and not the real content, so the content will be short
        # anyway.
        args_nostream = dict(kwargs, stream=False)
        _rewind_request_body(response.request)
        response2 = response.connection.send(request, **args_nostream)

        # needed to make NTLM auth compatible with requests-2.3.0

        # Consume content and release the original connection
        # to allow our new request to reuse the same one.
        _ = response2.content
        response2.raw.release_conn()
        if not ntlm_context.set_challenge_from_header(response2.headers.get(auth_header_field)):
            response2.history.append(response)
            return response2

        request = response2.request.copy()

        # this is important for some web applications that store
        # authentication-related info in cookies (it took a long time to
        # figure out)
        cookie = response2.headers.get("set-cookie")
        if cookie:
            request.headers["Cookie"] = cookie

        # build response
        # Get the response based on the challenge message
        request.headers[auth_header] = ntlm_context.get_authenticate_header()
        _rewind_request_body(response.request)
        response3 = response2.connection.send(request, **kwargs)

        # Update the history.
        response3.history.append(response)
        response3.history.append(response2)

        # Get the session_security object created by ntlm-auth for signing and
        # sealing of messages
        self.session_security = ntlm_context.session_security

        return response3

    def response_hook(self, r: Response, **kwargs: Any) -> Response:
        """The actual hook handler."""
        if r.status_code == 401:
            # Handle server auth.
            www_authenticate = r.headers.get("www-authenticate", "")
            auth_type = get_auth_type_from_header(www_authenticate)

            if auth_type is not None:
                return self.retry_using_http_ntlm_auth(
                    "www-authenticate", "Authorization", r, auth_type, kwargs
                )
        elif r.status_code == 407:
            # If we didn't have server auth, do proxy auth.
            proxy_authenticate = r.headers.get("proxy-authenticate", "")
            auth_type = get_auth_type_from_header(proxy_authenticate)
            if auth_type is not None:
                return self.retry_using_http_ntlm_auth(
                    "proxy-authenticate", "Proxy-Authorization", r, auth_type, kwargs
                )

        return r

    def __call__(self, r: PreparedRequest) -> PreparedRequest:
        # we must keep the connection because NTLM authenticates the
        # connection, not single requests
        r.headers["Connection"] = "Keep-Alive"

        r.register_hook("response", self.response_hook)
        return r

    def extract_username_and_password(self) -> Tuple[str, str]:
        if self.domain:
            return f"{self.domain}\\{self.username}", self.password
        return self.username, self.password
