from ntlm_auth import ntlm
from requests.auth import AuthBase

from .core import get_auth_type_from_header, get_server_cert
from .dance import HttpNtlmContext


class HttpNtlmAuth(AuthBase):
    """
    HTTP NTLM Authentication Handler for Requests.
    """

    def __init__(self, username, password, send_cbt=True):
        """Create an authentication handler for NTLM over HTTP.

        :param str username: Username in 'domain\\username' format
        :param str password: Password
        :param bool send_cbt: Will send the channel bindings over a
                              HTTPS channel (Default: True)
        """
        if ntlm is None:
            raise Exception("NTLM libraries unavailable")

        # parse the username
        try:
            self.domain, self.username = username.split("\\", 1)
        except ValueError:
            self.username = username
            self.domain = ""

        if self.domain:
            self.domain = self.domain.upper()
        self.password = password
        self.send_cbt = send_cbt

        # This exposes the encrypt/decrypt methods used to encrypt and decrypt
        # messages sent after ntlm authentication. These methods are utilised
        # by libraries that call requests_ntlm to encrypt and decrypt the
        # messages sent after authentication
        self.session_security = None

    def retry_using_http_ntlm_auth(
        self, auth_header_field, auth_header, response, auth_type, args
    ):
        # Get the certificate of the server if using HTTPS for CBT
        server_certificate_hash = get_server_cert(response, send_cbt=self.send_cbt)

        # Attempt to authenticate using HTTP NTLM challenge/response
        if auth_header in response.request.headers:
            return response

        content_length = int(
            response.request.headers.get("Content-Length", "0"), base=10
        )
        if hasattr(response.request.body, "seek"):
            if content_length > 0:
                response.request.body.seek(-content_length, 1)
            else:
                response.request.body.seek(0, 0)

        # Consume content and release the original connection
        # to allow our new request to reuse the same one.
        response.content
        response.raw.release_conn()
        request = response.request.copy()

        ntlm_context = HttpNtlmContext(
            self.username,
            self.password,
            domain=self.domain,
            auth_type=auth_type,
            server_certificate_hash=server_certificate_hash,
        )
        request.headers[auth_header] = ntlm_context.get_negotiate_header()

        # A streaming response breaks authentication.
        # This can be fixed by not streaming this request, which is safe
        # because the returned response3 will still have stream=True set if
        # specified in args. In addition, we expect this request to give us a
        # challenge and not the real content, so the content will be short
        # anyway.
        args_nostream = dict(args, stream=False)
        response2 = response.connection.send(request, **args_nostream)

        # needed to make NTLM auth compatible with requests-2.3.0

        # Consume content and release the original connection
        # to allow our new request to reuse the same one.
        response2.content
        response2.raw.release_conn()
        request = response2.request.copy()

        # this is important for some web applications that store
        # authentication-related info in cookies (it took a long time to
        # figure out)
        if response2.headers.get("set-cookie"):
            request.headers["Cookie"] = response2.headers.get("set-cookie")

        # get the challenge
        ntlm_context.set_challenge_from_header(response2.headers[auth_header_field])

        # build response
        # Get the response based on the challenge message
        request.headers[auth_header] = ntlm_context.get_authenticate_header()
        response3 = response2.connection.send(request, **args)

        # Update the history.
        response3.history.append(response)
        response3.history.append(response2)

        # Get the session_security object created by ntlm-auth for signing and
        # sealing of messages
        self.session_security = ntlm_context.session_security

        return response3

    def response_hook(self, r, **kwargs):
        """The actual hook handler."""
        if r.status_code == 401:
            # Handle server auth.
            www_authenticate = r.headers.get("www-authenticate", "").lower()
            auth_type = get_auth_type_from_header(www_authenticate)

            if auth_type is not None:
                return self.retry_using_http_ntlm_auth(
                    "www-authenticate", "Authorization", r, auth_type, kwargs
                )
        elif r.status_code == 407:
            # If we didn't have server auth, do proxy auth.
            proxy_authenticate = r.headers.get("proxy-authenticate", "").lower()
            auth_type = get_auth_type_from_header(proxy_authenticate)
            if auth_type is not None:
                return self.retry_using_http_ntlm_auth(
                    "proxy-authenticate", "Proxy-Authorization", r, auth_type, kwargs
                )

        return r

    def __call__(self, r):
        # we must keep the connection because NTLM authenticates the
        # connection, not single requests
        r.headers["Connection"] = "Keep-Alive"

        r.register_hook("response", self.response_hook)
        return r

    def extract_username_and_password(self):
        if self.domain:
            return "{}\\{}".format(self.domain, self.username), self.password
        return self.username, self.password
