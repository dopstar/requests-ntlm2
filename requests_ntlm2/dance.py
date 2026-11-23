"""NTLM message encoding, parsing, and challenge repair for HTTP."""

import base64
import logging
import struct
from typing import Optional, Tuple, Union

import ntlm_auth.constants
import ntlm_auth.ntlm
from ntlm_auth.gss_channel_bindings import GssChannelBindingsStruct
from ntlm_auth.messages import AuthenticateMessage, ChallengeMessage, NegotiateMessage
from ntlm_auth.session_security import SessionSecurity

from .constants import NtlmCompatibility


logger = logging.getLogger(__name__)


def get_ntlm_credentials(username: str, password: str) -> Tuple[str, str, str]:
    """Return the username, password, and domain from a bare or domain-prefixed username."""
    try:
        domain, username = username.split("\\", 1)
    except ValueError:
        domain = ""
    return username, password, domain


def is_challenge_message(msg: bytes) -> bool:
    """Check whether the message type field identifies a Type 2 NTLM challenge."""
    try:
        message_type = struct.unpack("<I", msg[8:12])[0]
        return message_type == ntlm_auth.constants.MessageTypes.NTLM_CHALLENGE
    except struct.error:
        return False


def is_challenge_message_valid(msg: bytes) -> bool:
    """Check whether the NTLM challenge parser can read the message."""
    try:
        _ = ChallengeMessage(msg)
        return True
    except struct.error:
        return False


def fix_target_info(challenge_msg: bytes) -> bytes:
    """Clear the target-info flag when an NTLM challenge's target info cannot be parsed."""
    if not is_challenge_message(challenge_msg):
        return challenge_msg

    if is_challenge_message_valid(challenge_msg):
        return challenge_msg

    signature = challenge_msg[:8]
    if signature != ntlm_auth.constants.NTLM_SIGNATURE:
        logger.warning("invalid signature: %r", signature)
        return challenge_msg

    negotiate_flags_raw = challenge_msg[20:24]
    try:
        negotiate_flags = struct.unpack("<I", negotiate_flags_raw)[0]
    except struct.error:
        logger.warning("Invalid Negotiate Flags: %s", negotiate_flags_raw)
        return challenge_msg

    if negotiate_flags & ntlm_auth.constants.NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO:
        try:
            negotiate_flags &= ~ntlm_auth.constants.NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO
            return challenge_msg[:20] + struct.pack("<I", negotiate_flags) + challenge_msg[24:]
        except struct.error:
            return challenge_msg
    return challenge_msg


class HttpNtlmContext(ntlm_auth.ntlm.NtlmContext):
    """Thin wrapper over ntlm_auth.ntlm.NtlmContext for HTTP"""

    def __init__(
        self,
        username: str,
        password: str,
        domain: Optional[str] = None,
        workstation: Optional[str] = None,
        cbt_data: Optional[GssChannelBindingsStruct] = None,
        ntlm_compatibility: int = NtlmCompatibility.NTLMv2_DEFAULT,
        auth_type: Optional[str] = None,
        ntlm_strict_mode: bool = False,
    ) -> None:
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
        :param ntlm_strict_mode: If False, attempt to repair malformed target info in Type 2 NTLM
                                challenge messages.
        """
        if auth_type not in ("NTLM", "Negotiate"):
            raise ValueError(
                f'Expected "NTLM" or "Negotiate" auth_type, got {auth_type}'
            )
        self._auth_type = auth_type
        self._challenge_token: Optional[bytes] = None
        self.ntlm_strict_mode = ntlm_strict_mode
        super().__init__(
            username,
            password,
            domain=domain,
            workstation=workstation,
            cbt_data=cbt_data,
            ntlm_compatibility=ntlm_compatibility,
        )

    @property
    def negotiate_message(self) -> Optional[NegotiateMessage]:
        """Return the negotiate message generated by the backend, if any."""
        return self._negotiate_message

    @negotiate_message.setter
    def negotiate_message(self, value: Optional[NegotiateMessage]) -> None:
        self._negotiate_message = value

    @property
    def challenge_message(self) -> Optional[ChallengeMessage]:
        """Return the challenge message parsed by the backend, if any."""
        return self._challenge_message

    @challenge_message.setter
    def challenge_message(self, value: Optional[ChallengeMessage]) -> None:
        self._challenge_message = value

    @property
    def authenticate_message(self) -> Optional[AuthenticateMessage]:
        """Return the authenticate message generated by the backend, if any."""
        return self._authenticate_message

    @authenticate_message.setter
    def authenticate_message(self, value: Optional[AuthenticateMessage]) -> None:
        self._authenticate_message = value

    @property
    def session_security(self) -> Optional[SessionSecurity]:
        """Return the signing and sealing context created during authentication, if any."""
        return self._session_security

    @session_security.setter
    def session_security(self, value: Optional[SessionSecurity]) -> None:
        self._session_security = value

    def create_negotiate_message(self) -> bytes:
        """Generate the initial NTLM message and return it as base64 bytes."""
        msg = self.step()
        return base64.b64encode(msg)

    def parse_challenge_message(self, msg2: Union[str, bytes]) -> None:
        """Decode and store the challenge, repairing malformed target info in non-strict mode."""
        challenge_msg = base64.b64decode(msg2)

        if self.ntlm_strict_mode:
            self._challenge_token = challenge_msg
        else:
            fixed_challenge_msg = fix_target_info(challenge_msg)
            if fixed_challenge_msg != challenge_msg:
                logger.debug("original challenge: %s", base64.b64encode(challenge_msg))
                logger.debug("modified challenge: %s", base64.b64encode(fixed_challenge_msg))
            self._challenge_token = fixed_challenge_msg

    def create_authenticate_message(self) -> bytes:
        """Generate a response to the stored challenge and return it as base64 bytes."""
        msg = self.step(self._challenge_token)
        return base64.b64encode(msg)

    def get_negotiate_header(self) -> str:
        """Return the HTTP authentication scheme followed by the encoded negotiate message."""
        negotiate_message = self.create_negotiate_message().decode("ascii")
        return f"{self._auth_type} {negotiate_message}"

    def set_challenge_from_header(self, raw_header_value: Optional[str]) -> None:
        """Find and store the challenge token for this context's HTTP authentication scheme."""
        if not raw_header_value:
            return None

        match_strings = (
            f"{self._auth_type} ",
            f"Proxy-Authenticate: {self._auth_type} ",
            f"WWW-Authenticate: {self._auth_type} ",
        )
        for header_value in raw_header_value.split(","):
            header_value = header_value.strip()
            normalized_header = header_value.lower()
            for auth_strip in match_strings:
                if normalized_header.startswith(auth_strip.lower()):
                    challenge = header_value[len(auth_strip):]
                    self.parse_challenge_message(challenge)
                    return
        return None

    def get_authenticate_header(self) -> str:
        """Return the HTTP authentication scheme followed by the encoded authenticate message."""
        authenticate_message = self.create_authenticate_message().decode("ascii")
        return f"{self._auth_type} {authenticate_message}"
