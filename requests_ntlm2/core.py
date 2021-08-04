import binascii
import logging
import struct
import sys
import warnings

import ntlm_auth.constants
from aenum import IntFlag, extend_enum
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from ntlm_auth.gss_channel_bindings import GssChannelBindingsStruct
from ntlm_auth.messages import ChallengeMessage
from requests.packages.urllib3.response import HTTPResponse


logger = logging.getLogger(__name__)


class NtlmCompatibility(object):
    # see Microsoft doc on compatibility levels here: https://bit.ly/2OWZVxp
    LM_AND_NTLMv1 = 0
    LM_AND_NTLMv1_WITH_ESS = 1
    NTLMv1_WITH_ESS = 2
    NTLMv2_DEFAULT = 3
    NTLMv2_LEVEL4 = 4
    NTLMv2_LEVEL5 = 5


class NegotiateFlags(IntFlag):
    # Indicates that Unicode strings are supported for use
    # in security buffer data.
    NEGOTIATE_UNICODE = 0x00000001

    # Indicates that OEM strings are supported for use in security
    # buffer data.
    NEGOTIATE_OEM = 0x00000002

    # Requests that the server's authentication realm be included in
    # the Type 2 message.
    REQUEST_TARGET = 0x00000004

    # This flag's usage has not been identified.
    UNKNOWN_1 = 0x00000008

    # Specifies that authenticated communication between the client and
    # server should carry a digital signature (message integrity).
    NEGOTIATE_SIGN = 0x00000010

    # Specifies that authenticated communication between the client and
    # server should be encrypted (message confidentiality).
    NEGOTIATE_SEAL = 0x00000020

    # Indicates that datagram authentication is being used.
    NEGOTIATE_DATAGRAM_STYLE = 0x00000040

    # Indicates that the Lan Manager Session Key should be used for
    # signing and sealing authenticated communications.
    NEGOTIATE_LAN_MANAGER_KEY = 0x00000080

    # This flag's usage has not been identified.
    NEGOTIATE_NETWARE = 0x00000100

    # Indicates that NTLM authentication is being used.
    NEGOTIATE_NTLM = 0x00000200

    # This flag's usage has not been identified.
    UNKNOWN_2 = 0x00000400

    # Sent by the client in the Type 3 message to indicate that an anonymous
    # context has been established. This also affects the response fields.
    NEGOTIATE_ANONYMOUS = 0x00000800

    # Sent by the client in the Type 1 message to indicate that the name of the
    # domain in which the client workstation has membership is included in the
    # message. This is used by the server to determine whether the client is
    # eligible for local authentication.
    NEGOTIATE_DOMAIN_SUPPLIED = 0x00001000

    # Sent by the client in the Type 1 message to indicate that the client
    # workstation's name is included in the message. This is used by the server
    # to determine whether the client is eligible for local authentication.
    NEGOTIATE_WORKSTATION_SUPPLIED = 0x00002000

    # Sent by the server to indicate that the server and client are on the
    # same machine. Implies that the client may use the established local
    # credentials for authentication instead of calculating a response to the challenge.
    NEGOTIATE_LOCAL_CALL = 0x00004000

    # Indicates that authenticated communication between the client and
    # server should be signed with a "dummy" signature.
    NEGOTIATE_ALWAYS_SIGN = 0x00008000

    # Sent by the server in the Type 2 message to indicate that the target
    # authentication realm is a domain.
    TARGET_TYPE_DOMAIN = 0x00010000

    # Sent by the server in the Type 2 message to indicate that the target
    # authentication realm is a server.
    TARGET_TYPE_SERVER = 0x00020000

    # Sent by the server in the Type 2 message to indicate that the target
    # authentication realm is a share.
    # Presumably, this is for share-level authentication. Usage is unclear.
    TARGET_TYPE_SHARE = 0x00040000

    # Indicates that the NTLM2 signing and sealing scheme should be used for
    # protecting authenticated communications. Note that this refers to a
    # particular session security scheme, and is not related to the use of
    # NTLMv2 authentication. This flag can, however, have an effect on the
    # response calculations
    NEGOTIATE_NTLMv2_KEY = 0x00080000

    # This flag's usage has not been identified.
    REQUEST_INIT_RESPONSE = 0x00100000
    # This flag's usage has not been identified.
    REQUEST_ACCEPT_RESPONSE = 0x00200000
    # This flag's usage has not been identified.
    REQUEST_NON_NT_SESSION_KEY = 0x00400000

    # Sent by the server in the Type 2 message to indicate that it is including
    # a Target Information block in the message. The Target Information block is
    # used in the calculation of the NTLMv2 response.
    NEGOTIATE_TARGET_INFO = 0x00800000


_DYNAMIC_NTLM_FLAGS = {
    # This flag's usage has not been identified.
    "UNKNOWN_3": 0x01000000,

    # This flag's usage has not been identified.
    "UNKNOWN_4": 0x02000000,

    # This flag's usage has not been identified.
    "UNKNOWN_5": 0x04000000,

    # This flag's usage has not been identified.
    "UNKNOWN_6": 0x08000000,

    # This flag's usage has not been identified.
    "UNKNOWN_7": 0x10000000,

    # Indicates that 128-bit encryption is supported.
    "NEGOTIATE_128": 0x20000000,

    # Indicates that the client will provide an encrypted master key in
    # the "Session Key" field of the Type 3 message.
    "NEGOTIATE_KEY_EXCHANGE": 0x40000000,

    # Indicates that 56-bit encryption is supported.
    "NEGOTIATE_56": 0x80000000
}

for k, v in _DYNAMIC_NTLM_FLAGS.items():
    try:
        extend_enum(NegotiateFlags, k, v)
    except OverflowError:
        logger.warning("not defining '%s.%s' enum member because its beyond maxint")


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
            logger.debug("unable to get server certificate")
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
        message_type = struct.unpack("<I", msg[8:12])[0]
        return message_type == ntlm_auth.constants.MessageTypes.NTLM_CHALLENGE
    except struct.error:
        return False


def is_challenge_message_valid(msg):
    try:
        _ = ChallengeMessage(msg)
        return True
    except struct.error:
        return False


def fix_target_info(challenge_msg):
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


def noop():
    pass
