import binascii
import logging
import sys
import warnings

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from requests.packages.urllib3.response import HTTPResponse


logger = logging.getLogger(__name__)


class UnknownSignatureAlgorithmOID(Warning):
    pass


def get_server_cert(response, send_cbt=False):
    """
    Get the certificate at the request_url and return it as a hash. Will
    get the raw socket from the original response from the server. This
    socket is then checked if it is an SSL socket and then used to get the
    hash of the certificate. The certificate hash is then used with NTLMv2
    authentication for Channel Binding Tokens support. If the raw object
    is not a urllib3 HTTPReponse (default with requests) then no
    certificate will be returned.

    :param response: The original 401 response from the server
    :param send_cbt: Will send the channel bindings over a
                     HTTPS channel (Default: False)
    :return: The hash of the DER encoded certificate at the
             request_url or None if not a HTTPS endpoint
    """
    if send_cbt:
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
                return get_certificate_hash(server_certificate)
        else:
            logger.warning(
                "Requests is running with a non urllib3 backend,"
                " cannot retrieve server certificate for CBT"
            )
    return None


def get_certificate_hash(certificate_der):
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
    certificate_hash = binascii.hexlify(certificate_hash_bytes).decode().upper()

    return certificate_hash


def get_auth_type_from_header(header):
    """
    Given a WWW-Authenticate or Proxy-Authenticate header, returns the
    authentication type to use. We prefer NTLM over Negotiate if the server
    suppports it.
    """
    if "ntlm" in header:
        return "NTLM"
    elif "negotiate" in header:
        return "Negotiate"
    return None


def get_ntlm_credentials(username, password):
    try:
        domain, username = username.split("\\", 1)
    except ValueError:
        domain = ""
    return username, password, domain
