import binascii
import logging
import warnings
from typing import TYPE_CHECKING, Optional

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from ntlm_auth.gss_channel_bindings import GssChannelBindingsStruct
from requests import Response


if TYPE_CHECKING:
    from urllib3.response import HTTPResponse
else:
    from requests.packages.urllib3.response import HTTPResponse


logger = logging.getLogger(__name__)


class UnknownSignatureAlgorithmOID(Warning):
    pass


def get_server_cert(response: Response) -> Optional[bytes]:
    """
    Get the certificate at the request_url and return it as a hash. Will
    get the raw socket from the original response from the server. This
    socket is then checked if it is an SSL socket and then used to get the
    hash of the certificate. The certificate hash is then used with NTLMv2
    authentication for Channel Binding Tokens support. If the raw object
    is not urllib3 HTTPResponse (default with requests) then no certificate
    will be returned.

    :param response: The original 401 response from the server
    :return: The hash of the DER encoded certificate at the request_url or None
        if not an HTTPS url.
    """
    raw_response = response.raw

    if isinstance(raw_response, HTTPResponse):
        try:
            fp = raw_response._fp
            if fp is None:
                return None
            socket = getattr(fp.fp.raw, "_sock")
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
    return None


def get_certificate_hash_bytes(certificate_der: bytes) -> Optional[bytes]:
    # https://tools.ietf.org/html/rfc5929#section-4.1
    cert = x509.load_der_x509_certificate(certificate_der, default_backend())

    try:
        hash_algorithm = cert.signature_hash_algorithm
        if hash_algorithm is None:
            raise UnsupportedAlgorithm("The certificate signature has no separate hash algorithm")
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


def get_cbt_data(response: Response) -> Optional[GssChannelBindingsStruct]:
    """
    Create Channel Binding for TLS data

    See:
      - https://tools.ietf.org/html/rfc5929
      - https://github.com/jborean93/ntlm-auth#ntlmv2
      - https://github.com/requests/requests-ntlm/pull/116#discussion_r325961121
      - Microsoft support article on NTLM authentication failures:
        https://support.microsoft.com/en-za/help/976918/authentication-failure-from-non-windows-ntlm-or-kerberos-servers

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
