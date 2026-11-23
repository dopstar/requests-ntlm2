"""Protocol constants and LAN Manager compatibility levels."""


class NtlmCompatibility:
    """Name the LAN Manager compatibility levels accepted by the NTLM backend."""

    # see Microsoft doc on compatibility levels here: https://bit.ly/2OWZVxp
    LM_AND_NTLMv1 = 0
    LM_AND_NTLMv1_WITH_ESS = 1
    NTLMv1_WITH_ESS = 2
    NTLMv2_DEFAULT = 3
    NTLMv2_LEVEL4 = 4
    NTLMv2_LEVEL5 = 5


HTTP_VERSION_10 = "HTTP/1.0"
HTTP_VERSION_11 = "HTTP/1.1"
DEFAULT_HTTP_VERSION = HTTP_VERSION_10

IO_WAIT_TIMEOUT = 0.1
MAX_HEADER_LINE_LENGTH = 65536
ASSUMED_HTTP09_STATUS_LINES = (
    ("HTTP/0.9", 200, ""),
    ("HTTP/0.9", 200, "OK"),
)
