import base64
import logging

import ntlm_auth.ntlm

from .core import NtlmCompatibility, fix_target_info


logger = logging.getLogger(__name__)


class HttpNtlmContext(ntlm_auth.ntlm.NtlmContext):
    """Thin wrapper over ntlm_auth.ntlm.NtlmContext for HTTP"""

    def __init__(
        self,
        username,
        password,
        domain=None,
        workstation=None,
        cbt_data=None,
        ntlm_compatibility=NtlmCompatibility.NTLMv2_DEFAULT,
        auth_type=None,
        ntlm_strict_mode=False,
    ):
        r"""
        Initialises a NTLM context to use when authenticating using the NTLM
        protocol.
        Initialises the NTLM context to use when sending and receiving messages
        to and from the server. You should be using this object as it supports
        NTLMv2 authenticate and it easier to use than before. It also brings in
        the ability to use signing and sealing with session_security and
        generate a MIC structure.

        :param username: The username to authenticate with
        :param password: The password for the username
        :param domain: The domain part of the username (None if n/a)
        :param workstation: The localworkstation (None if n/a)
        :param cbt_data: A GssChannelBindingsStruct or None to bind channel
            data with the auth process. See: https://tools.ietf.org/html/rfc5929
        :param ntlm_compatibility: (Default 3)
            The Lan Manager Compatibility Level to use with the auth message
            This is set by an Administrator in the registry key
            'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'
            The values correspond to the following;
                0 : LM and NTLMv1
                1 : LM, NTLMv1 and NTLMv1 with Extended Session Security
                2 : NTLMv1 and NTLMv1 with Extended Session Security
                3-5 : NTLMv2 Only
            Note: Values 3 to 5 are no different from a client perspective
        :param auth_type: either 'NTLM' or 'Negotiate'
        :param ntlm_strict_mode: If False, tries to Type 2 (ie challenge response) NTLM message
                                that does not conform to the NTLM spec
        """
        if auth_type not in ("NTLM", "Negotiate"):
            raise ValueError(
                'Expected "NTLM" or "Negotiate" auth_type, got {}'.format(auth_type)
            )
        self._auth_type = auth_type
        self._challenge_token = None
        self.ntlm_strict_mode = ntlm_strict_mode
        super(HttpNtlmContext, self).__init__(
            username,
            password,
            domain=domain,
            workstation=workstation,
            cbt_data=cbt_data,
            ntlm_compatibility=ntlm_compatibility,
        )

    @property
    def negotiate_message(self):
        return self._negotiate_message

    @negotiate_message.setter
    def negotiate_message(self, value):
        self._negotiate_message = value

    @property
    def challenge_message(self):
        return self._challenge_message

    @challenge_message.setter
    def challenge_message(self, value):
        self._challenge_message = value

    @property
    def authenticate_message(self):
        return self._authenticate_message

    @authenticate_message.setter
    def authenticate_message(self, value):
        self._authenticate_message = value

    @property
    def session_security(self):
        return self._session_security

    @session_security.setter
    def session_security(self, value):
        self._session_security = value

    def create_negotiate_message(self):
        msg = self.step()
        return base64.b64encode(msg)

    def parse_challenge_message(self, msg2):
        challenge_msg = base64.b64decode(msg2)
        if self.ntlm_strict_mode:
            self._challenge_token = challenge_msg
        else:
            fixed_challenge_msg = fix_target_info(challenge_msg)
            if fixed_challenge_msg != challenge_msg:
                logger.debug("original challenge: %s", base64.b64encode(challenge_msg))
                logger.debug("modified challenge: %s", base64.b64encode(fixed_challenge_msg))
            self._challenge_token = fixed_challenge_msg

    def create_authenticate_message(self):
        msg = self.step(self._challenge_token)
        return base64.b64encode(msg)

    def get_negotiate_header(self):
        negotiate_message = self.create_negotiate_message().decode("ascii")
        result = u"{auth_type} {negotiate_message}".format(
            auth_type=self._auth_type, negotiate_message=negotiate_message
        )
        return result

    def set_challenge_from_header(self, raw_header_value):
        if not raw_header_value:
            return None

        match_strings = (
            "{} ".format(self._auth_type),
            "{}: {} ".format("Proxy-Authenticate", self._auth_type),
            "{}: {} ".format("WWW-Authenticate", self._auth_type),
        )
        for header_value in raw_header_value.split(","):
            header_value = header_value.strip()
            for auth_strip in match_strings:
                if header_value.startswith(auth_strip):
                    challenge = header_value.replace(auth_strip, "")
                    return self.parse_challenge_message(challenge)
        return None

    def get_authenticate_header(self):
        authenticate_message = self.create_authenticate_message()
        authenticate_message = authenticate_message.decode("ascii")
        return u"{auth_type} {authenticate_message}".format(
            auth_type=self._auth_type,
            authenticate_message=authenticate_message
        )
