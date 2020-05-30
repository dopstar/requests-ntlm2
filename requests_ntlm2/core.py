import base64
import binascii
import logging
import struct
import sys
import warnings

import ntlm_auth.constants
from aenum import IntFlag
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from ntlm_auth.gss_channel_bindings import GssChannelBindingsStruct
from ntlm_auth.messages import ChallengeMessage
from requests.packages.urllib3.response import HTTPResponse


logger = logging.getLogger(__name__)


class NegotiateFlags(IntFlag):
    """
    [MS-NLMP] v28.0 2016-07-14

    2.2.2.5 NEGOTIATE
    During NTLM authentication, each of the following flags is a possible value
    of the NegotiateFlags field of the NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE and
    AUTHENTICATE_MESSAGE, unless otherwise noted. These flags define client or
    server NTLM capabilities supported by the sender.
    """
    NTLMSSP_NEGOTIATE_56 = 0x80000000
    NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000
    NTLMSSP_NEGOTIATE_128 = 0x20000000
    NTLMSSP_RESERVED_R1 = 0x10000000
    NTLMSSP_RESERVED_R2 = 0x08000000
    NTLMSSP_RESERVED_R3 = 0x04000000
    NTLMSSP_NEGOTIATE_VERSION = 0x02000000
    NTLMSSP_RESERVED_R4 = 0x01000000
    NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000
    NTLMSSP_REQUEST_NON_NT_SESSION_KEY = 0x00400000
    NTLMSSP_RESERVED_R5 = 0x00200000
    NTLMSSP_NEGOTIATE_IDENTITY = 0x00100000
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
    NTLMSSP_RESERVED_R6 = 0x00040000
    NTLMSSP_TARGET_TYPE_SERVER = 0x00020000
    NTLMSSP_TARGET_TYPE_DOMAIN = 0x00010000
    NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
    NTLMSSP_RESERVED_R7 = 0x00004000
    NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000
    NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x00001000
    NTLMSSP_ANOYNMOUS = 0x00000800
    NTLMSSP_RESERVED_R8 = 0x00000400
    NTLMSSP_NEGOTIATE_NTLM = 0x00000200
    NTLMSSP_RESERVED_R9 = 0x00000100
    NTLMSSP_NEGOTIATE_LM_KEY = 0x00000080
    NTLMSSP_NEGOTIATE_DATAGRAM = 0x00000040
    NTLMSSP_NEGOTIATE_SEAL = 0x00000020
    NTLMSSP_NEGOTIATE_SIGN = 0x00000010
    NTLMSSP_RESERVED_R10 = 0x00000008
    NTLMSSP_REQUEST_TARGET = 0x00000004
    NTLMSSP_NEGOTIATE_OEM = 0x00000002
    NTLMSSP_NEGOTIATE_UNICODE = 0x00000001


class NtlmCompatibility(object):
    # see Microsoft doc on compatibility levels here: https://bit.ly/2OWZVxp
    LM_AND_NTLMv1 = 0
    LM_AND_NTLMv1_WITH_ESS = 1
    NTLMv1_WITH_ESS = 2
    NTLMv2_DEFAULT = 3
    NTLMv2_LEVEL4 = 4
    NTLMv2_LEVEL5 = 5


class UnknownSignatureAlgorithmOID(Warning):
    pass


def get_server_cert(response):
    """
    Get the certificate at the request_url and return it as a hash. Will
    get the raw socket from the original response from the server. This
    socket is then checked if it is an SSL socket and then used to get the
    hash of the certificate. The certificate hash is then used with NTLMv2
    authentication for Channel Binding Tokens support. If the raw object
    is not a urllib3 HTTPReponse (default with requests) then no
    certificate will be returned.

    :param response: The original 401 response from the server
    :return: The hash of the DER encoded certificate at the request_url or None if not a HTTPS url
    """
    raw_response = response.raw

    if isinstance(raw_response, HTTPResponse):
        try:
            if sys.version_info > (3, 0):
                socket = raw_response._fp.fp.raw._sock
            else:
                socket = raw_response._fp.fp._sock
        except AttributeError:
            return None

        try:
            server_certificate = socket.getpeercert(True)
        except AttributeError:
            pass
        else:
            return get_certificate_hash_bytes(server_certificate)
    else:
        logger.warning(
            "Requests is running with a non urllib3 backend,"
            " cannot retrieve server certificate for CBT"
        )


def get_certificate_hash_bytes(certificate_der):
    # https://tools.ietf.org/html/rfc5929#section-4.1
    cert = x509.load_der_x509_certificate(certificate_der, default_backend())

    try:
        hash_algorithm = cert.signature_hash_algorithm
    except UnsupportedAlgorithm as ex:
        logger.exception("e=")
        warnings.warn(
            "Failed to get signature algorithm from certificate, "
            "unable to pass channel bindings: %s" % str(ex),
            UnknownSignatureAlgorithmOID,
        )
        return None

    # if the cert signature algorithm is either md5 or sha1 then use sha256
    # otherwise use the signature algorithm
    if hash_algorithm.name in ["md5", "sha1"]:
        digest = hashes.Hash(hashes.SHA256(), default_backend())
    else:
        digest = hashes.Hash(hash_algorithm, default_backend())

    digest.update(certificate_der)
    certificate_hash_bytes = digest.finalize()
    logger.debug("peer/server cert hash: %s", binascii.hexlify(certificate_hash_bytes))
    return certificate_hash_bytes


def get_auth_type_from_header(header):
    """
    Given a WWW-Authenticate or Proxy-Authenticate header, returns the
    authentication type to use. We prefer NTLM over Negotiate if the server
    suppports it.
    """
    if "ntlm" in header.lower():
        return "NTLM"
    elif "negotiate" in header.lower():
        return "Negotiate"
    return None


def get_ntlm_credentials(username, password):
    try:
        domain, username = username.split("\\", 1)
    except ValueError:
        domain = ""
    return username, password, domain


def get_cbt_data(response):
    """
    Create Channel Binding for TLS data

    See:
      - https://tools.ietf.org/html/rfc5929
      - https://github.com/jborean93/ntlm-auth#ntlmv2
      - https://github.com/requests/requests-ntlm/pull/116#discussion_r325961121
      - https://support.microsoft.com/en-za/help/976918/authentication-failure-from-non-windows-ntlm-or-kerberos-servers  # noqa

    :param response: HTTP Response object
    """

    cert_hash_bytes = get_server_cert(response)
    if not cert_hash_bytes:
        logger.debug("server cert not found, channel binding tokens (CBT) wont be used")
        return None

    channel_binding_type = b"tls-server-end-point"  # https://tools.ietf.org/html/rfc5929#section-4
    data_type = GssChannelBindingsStruct.APPLICATION_DATA

    cbt_data = GssChannelBindingsStruct()
    cbt_data[data_type] = b":".join([channel_binding_type, cert_hash_bytes])
    logger.debug("cbt data: %s", cbt_data.get_data())
    return cbt_data


def is_challenge_message(msg):
    try:
        message_type = struct.unpack('<I', msg[8:12])[0]
        if message_type == ntlm_auth.constants.MessageTypes.NTLM_CHALLENGE:
            return True
    except struct.error:
        pass
    logger.warning('Invalid message type: %s', msg[8:12])
    return False


def is_challenge_message_valid(msg):
    try:
        _ = ChallengeMessage(msg)
        return True
    except struct.error:
        return False


def fix_target_info(challenge_msg):
    if is_challenge_message_valid(challenge_msg):
        return challenge_msg

    if not is_challenge_message(challenge_msg):
        return challenge_msg

    msg = challenge_msg

    signature = msg[:8]
    if signature != ntlm_auth.constants.NTLM_SIGNATURE:
        logger.warning('invalid signature: %r', signature)
        return msg

    negotiate_flags_raw = msg[20:24]
    try:
        negotiate_flags = struct.unpack("<I", negotiate_flags_raw)[0]
    except struct.error:
        logger.warning('Invalid Negotiate Flags: %s', negotiate_flags_raw)
        return msg

    if negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO:
        try:
            negotiate_flags &= ~NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO
            msg = msg[:20] + struct.pack('<I', negotiate_flags.value) + msg[24:]
            logger.debug('original challenge: %s', base64.b64encode(challenge_msg))
            logger.debug('fixed challenge: %s', base64.b64encode(msg))
            return msg
        except struct.error:
            return challenge_msg
    else:
        logger.debug('no target info set')
    return challenge_msg
