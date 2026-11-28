import base64
import struct

import pytest

from requests_ntlm2.dance import HttpNtlmContext
from requests_ntlm2.proxy.adapters.ntlm import HttpNtlmAdapter
from requests_ntlm2.proxy.connection import VerifiedHTTPSConnection


def _av(av_id, data):
    return struct.pack("<HH", av_id, len(data)) + data


def _build_challenge(ti_bytes, ti_len=None, ti_off=None):
    sig = b"NTLMSSP\x00"
    mtype = struct.pack("<I", 2)
    flags = 0x00000001 | 0x00000002 | 0x00000400 | 0x00080000 | 0x00800000 | 0x02000000
    server_challenge = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    reserved = b"\x00" * 8
    header_len = 48
    target_name = struct.pack("<HHI", 0, 0, header_len)
    if ti_len is None:
        ti_len = len(ti_bytes)
    if ti_off is None:
        ti_off = header_len
    target_info = struct.pack("<HHI", ti_len, ti_len, ti_off)
    return sig + mtype + target_name + struct.pack("<I", flags) + server_challenge + reserved + target_info + ti_bytes


_DOMAIN_UTF16 = "DOMAIN".encode("utf-16le")
_VALID_TI = _av(1, _DOMAIN_UTF16) + _av(2, _DOMAIN_UTF16) + _av(0, b"")
VALID_CHALLENGE = _build_challenge(_VALID_TI)
# malformed: the target-info length/offset point far beyond the end of the message
MALFORMED_CHALLENGE = _build_challenge(b"", ti_len=0x7FFF, ti_off=0x7FFF)


def _tunnel_context():
    """Build the context exactly as VerifiedHTTPSConnection._tunnel builds it."""
    return HttpNtlmContext(
        "user",
        "password",
        domain="DOMAIN",
        auth_type="NTLM",
        ntlm_strict_mode=VerifiedHTTPSConnection.ntlm_strict_mode,
    )


def _answer(ctx, challenge):
    ctx.create_negotiate_message()
    ctx.parse_challenge_message(base64.b64encode(challenge))
    return ctx.create_authenticate_message()


class TestHttpNtlmAdapterStrictMode:
    def test_setup_writes_strict_mode_to_the_tunnel_connection_class(self):
        adapter = HttpNtlmAdapter("DOMAIN\\user", "password", ntlm_strict_mode=True)
        try:
            # _tunnel reads the flag from VerifiedHTTPSConnection, so that is
            # the class _setup must write it to.
            assert VerifiedHTTPSConnection.ntlm_strict_mode is True
        finally:
            adapter.close()

    def test_tunnel_path_refuses_malformed_challenge_when_strict(self):
        adapter = HttpNtlmAdapter("DOMAIN\\user", "password", ntlm_strict_mode=True)
        try:
            with pytest.raises(struct.error):
                _answer(_tunnel_context(), MALFORMED_CHALLENGE)
        finally:
            adapter.close()

    def test_tunnel_path_repairs_malformed_challenge_when_not_strict(self):
        adapter = HttpNtlmAdapter("DOMAIN\\user", "password", ntlm_strict_mode=False)
        try:
            response = _answer(_tunnel_context(), MALFORMED_CHALLENGE)
            assert base64.b64decode(response)
        finally:
            adapter.close()

    def test_tunnel_path_answers_valid_challenge_when_strict(self):
        adapter = HttpNtlmAdapter("DOMAIN\\user", "password", ntlm_strict_mode=True)
        try:
            response = _answer(_tunnel_context(), VALID_CHALLENGE)
            assert base64.b64decode(response)
        finally:
            adapter.close()

    def test_auth_path_control_refuses_malformed_challenge_when_strict(self):
        ctx = HttpNtlmContext(
            "user", "password", domain="DOMAIN", auth_type="NTLM", ntlm_strict_mode=True
        )
        with pytest.raises(struct.error):
            _answer(ctx, MALFORMED_CHALLENGE)

    def test_auth_path_control_answers_valid_challenge_when_strict(self):
        ctx = HttpNtlmContext(
            "user", "password", domain="DOMAIN", auth_type="NTLM", ntlm_strict_mode=True
        )
        response = _answer(ctx, VALID_CHALLENGE)
        assert base64.b64decode(response)
