import base64

import faker
import mock
import ntlm_auth.ntlm
import pytest

import requests_ntlm2
import requests_ntlm2.core
import requests_ntlm2.dance


class TestHttpNtlmContext(object):
    fake = faker.Factory.create()

    def test__init(self):
        error_msg = 'Expected "NTLM" or "Negotiate" auth_type, got None'
        with pytest.raises(ValueError, match=error_msg):
            requests_ntlm2.dance.HttpNtlmContext("username", "password")

    def test__init__ntlm(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="NTLM")
        assert isinstance(ctx, requests_ntlm2.dance.HttpNtlmContext)
        assert isinstance(ctx, ntlm_auth.ntlm.NtlmContext)
        assert ctx._auth_type == "NTLM"
        assert ctx._challenge_token is None
        assert ctx.ntlm_compatibility == requests_ntlm2.NtlmCompatibility.NTLMv2_DEFAULT
        assert ctx.username == username
        assert ctx.password == password
        assert ctx.domain is None
        assert ctx.cbt_data is None

    def test__init__negotiate(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="Negotiate")
        assert isinstance(ctx, requests_ntlm2.dance.HttpNtlmContext)
        assert isinstance(ctx, ntlm_auth.ntlm.NtlmContext)
        assert ctx._auth_type == "Negotiate"
        assert ctx._challenge_token is None
        assert ctx.ntlm_compatibility == requests_ntlm2.NtlmCompatibility.NTLMv2_DEFAULT
        assert ctx.username == username
        assert ctx.password == password
        assert ctx.domain is None
        assert ctx.cbt_data is None

    def test_get_negotiate_header(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="NTLM")
        authenticate_header = ctx.get_negotiate_header()
        assert  authenticate_header == "NTLM TlRMTVNTUAABAAAAMYCI4gAAAAAoAAAAAAAAACgAAAAGAbEdAAAADw=="  # noqa

    def test_get_authenticate_header(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, domain="", auth_type="NTLM")
        _ = ctx.get_negotiate_header()  # this is necessary
        challenge = (
            "NTLM TlRMTVNTUAACAAAAAAAAAAAAAAAyAojgAnH/LKem1bAAAA"
            "AAAAAAAH4AfgA4AAAABQCTCAAAAA8CAAwARABFAFQATgBTAFcAA"
            "QAaAFMARwAtADAAMgAxADQAMwAwADAAMAAxADUABAAUAEQARQBU"
            "AE4AUwBXAC4AVwBJAE4AAwAwAHMAZwAtADAAMgAxADQAMwAwADAA"
            "MAAxADUALgBkAGUAdABuAHMAdwAuAHcAaQBuAAAAAAA="
        )
        ctx.set_challenge_from_header(challenge)

        authenticate_header = ctx.get_authenticate_header()
        assert authenticate_header.startswith("NTLM ")
        decoded_authenticate_data = base64.b64decode(authenticate_header.split()[1])
        assert decoded_authenticate_data[:9] == b"NTLMSSP\x00\x03"

    def test_set_challenge_from_header(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="NTLM")
        assert ctx._auth_type == "NTLM"

        challenge = (
            "NTLM TlRMTVNTUAACAAAAAAAAAAAAAAAyAojgAnH/LKem1bAAAA"
            "AAAAAAAH4AfgA4AAAABQCTCAAAAA8CAAwARABFAFQATgBTAFcAA"
            "QAaAFMARwAtADAAMgAxADQAMwAwADAAMAAxADUABAAUAEQARQBU"
            "AE4AUwBXAC4AVwBJAE4AAwAwAHMAZwAtADAAMgAxADQAMwAwADAA"
            "MAAxADUALgBkAGUAdABuAHMAdwAuAHcAaQBuAAAAAAA="
        )
        ctx.set_challenge_from_header(challenge)
        assert ctx._challenge_token == (
            b"NTLMSSP"
            b"\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x002\x02\x88\xe0\x02q\xff,"
            b"\xa7\xa6\xd5\xb0\x00\x00\x00\x00\x00\x00\x00\x00~\x00~\x008\x00\x00\x00\x05\x00"
            b"\x93\x08\x00\x00\x00\x0f\x02\x00\x0c\x00D\x00E\x00T\x00N\x00S\x00W\x00\x01\x00"
            b"\x1a\x00S\x00G\x00-\x000\x002\x001\x004\x003\x000\x000\x000\x001\x005\x00\x04\x00"
            b"\x14\x00D\x00E\x00T\x00N\x00S\x00W\x00.\x00W\x00I\x00N\x00\x03\x000\x00s\x00g\x00"
            b"-\x000\x002\x001\x004\x003\x000\x000\x000\x001\x005\x00.\x00d\x00e\x00t\x00n\x00s"
            b"\x00w\x00.\x00w\x00i\x00n\x00\x00\x00\x00\x00"
        )

    def test_set_challenge_from_header__www_authenticate(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="NTLM")
        assert ctx._auth_type == "NTLM"

        challenge = (
            "WWW-Authenticate: NTLM TlRMTVNTUAACAAAAAAAAAAAAAAAyAojgAnH/LKem1bAAAA"
            "AAAAAAAH4AfgA4AAAABQCTCAAAAA8CAAwARABFAFQATgBTAFcAA"
            "QAaAFMARwAtADAAMgAxADQAMwAwADAAMAAxADUABAAUAEQARQBU"
            "AE4AUwBXAC4AVwBJAE4AAwAwAHMAZwAtADAAMgAxADQAMwAwADAA"
            "MAAxADUALgBkAGUAdABuAHMAdwAuAHcAaQBuAAAAAAA="
        )
        ctx.set_challenge_from_header(challenge)
        assert ctx._challenge_token == (
            b"NTLMSSP"
            b"\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x002\x02\x88\xe0\x02q\xff,"
            b"\xa7\xa6\xd5\xb0\x00\x00\x00\x00\x00\x00\x00\x00~\x00~\x008\x00\x00\x00\x05\x00"
            b"\x93\x08\x00\x00\x00\x0f\x02\x00\x0c\x00D\x00E\x00T\x00N\x00S\x00W\x00\x01\x00"
            b"\x1a\x00S\x00G\x00-\x000\x002\x001\x004\x003\x000\x000\x000\x001\x005\x00\x04\x00"
            b"\x14\x00D\x00E\x00T\x00N\x00S\x00W\x00.\x00W\x00I\x00N\x00\x03\x000\x00s\x00g\x00"
            b"-\x000\x002\x001\x004\x003\x000\x000\x000\x001\x005\x00.\x00d\x00e\x00t\x00n\x00s"
            b"\x00w\x00.\x00w\x00i\x00n\x00\x00\x00\x00\x00"
        )

    def test_set_challenge_from_header__proxy_authenticate(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="NTLM")
        assert ctx._auth_type == "NTLM"

        challenge = (
            "Proxy-Authenticate: NTLM TlRMTVNTUAACAAAAAAAAAAAAAAAyAojgAnH/LKem1bAAAA"
            "AAAAAAAH4AfgA4AAAABQCTCAAAAA8CAAwARABFAFQATgBTAFcAA"
            "QAaAFMARwAtADAAMgAxADQAMwAwADAAMAAxADUABAAUAEQARQBU"
            "AE4AUwBXAC4AVwBJAE4AAwAwAHMAZwAtADAAMgAxADQAMwAwADAA"
            "MAAxADUALgBkAGUAdABuAHMAdwAuAHcAaQBuAAAAAAA="
        )
        ctx.set_challenge_from_header(challenge)
        assert ctx._challenge_token == (
            b"NTLMSSP"
            b"\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x002\x02\x88\xe0\x02q\xff,"
            b"\xa7\xa6\xd5\xb0\x00\x00\x00\x00\x00\x00\x00\x00~\x00~\x008\x00\x00\x00\x05\x00"
            b"\x93\x08\x00\x00\x00\x0f\x02\x00\x0c\x00D\x00E\x00T\x00N\x00S\x00W\x00\x01\x00"
            b"\x1a\x00S\x00G\x00-\x000\x002\x001\x004\x003\x000\x000\x000\x001\x005\x00\x04\x00"
            b"\x14\x00D\x00E\x00T\x00N\x00S\x00W\x00.\x00W\x00I\x00N\x00\x03\x000\x00s\x00g\x00"
            b"-\x000\x002\x001\x004\x003\x000\x000\x000\x001\x005\x00.\x00d\x00e\x00t\x00n\x00s"
            b"\x00w\x00.\x00w\x00i\x00n\x00\x00\x00\x00\x00"
        )

    def test_set_challenge_from_header__invalid_header(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="NTLM")
        assert ctx._auth_type == "NTLM"

        challenge = (
            "Proxy-Authenticate: NTLM2 TlRMTVNTUAACAAAAAAAAAAAAAAAyAojgAnH/LKem1bAAAA"
            "AAAAAAAH4AfgA4AAAABQCTCAAAAA8CAAwARABFAFQATgBTAFcAA"
            "QAaAFMARwAtADAAMgAxADQAMwAwADAAMAAxADUABAAUAEQARQBU"
            "AE4AUwBXAC4AVwBJAE4AAwAwAHMAZwAtADAAMgAxADQAMwAwADAA"
            "MAAxADUALgBkAGUAdABuAHMAdwAuAHcAaQBuAAAAAAA="
        )
        ctx.set_challenge_from_header(challenge)
        assert ctx._challenge_token is None

    def test_set_challenge_from_header__no_header(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="NTLM")
        assert ctx._auth_type == "NTLM"

        challenge = None
        ctx.set_challenge_from_header(challenge)
        assert ctx._challenge_token is None

    def test_session_security(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="NTLM")
        assert ctx.session_security is None
        assert ctx._session_security is None

        ctx._session_security = self.fake.pystr()
        assert ctx._session_security is not None
        assert ctx.session_security == ctx._session_security

        ctx.session_security = None
        assert ctx.session_security is None
        assert ctx._session_security is None

    def test_challenge_message(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="NTLM")
        assert ctx.challenge_message is None
        assert ctx._challenge_message is None

        ctx._challenge_message = self.fake.pystr()
        assert ctx._challenge_message is not None
        assert ctx.challenge_message == ctx._challenge_message

        ctx.challenge_message = None
        assert ctx.challenge_message is None
        assert ctx._challenge_message is None

    def test_authenticate_message(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="NTLM")
        assert ctx.authenticate_message is None
        assert ctx._authenticate_message is None

        ctx._authenticate_message = self.fake.pystr()
        assert ctx._authenticate_message is not None
        assert ctx.authenticate_message == ctx._authenticate_message

        ctx.authenticate_message = None
        assert ctx.authenticate_message is None
        assert ctx._authenticate_message is None

    def test_negotiate_message(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="NTLM")
        assert ctx.negotiate_message is None
        assert ctx._negotiate_message is None

        ctx._negotiate_message = self.fake.pystr()
        assert ctx._negotiate_message is not None
        assert ctx.negotiate_message == ctx._negotiate_message

        ctx.negotiate_message = None
        assert ctx.negotiate_message is None
        assert ctx._negotiate_message is None

    def test_parse_challenge_message(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(
            username,
            password,
            auth_type="NTLM",
            ntlm_strict_mode=True
        )
        msg = "TlRMTVNTUAACAAAAAAAAAAAAAAAGgokAmuCpt5hD4IIAAAAAAAAAAAAAAAAAAAAA"
        ctx.parse_challenge_message(msg)
        assert ctx._challenge_token == base64.b64decode(msg)

        ctx = requests_ntlm2.dance.HttpNtlmContext(
            username,
            password,
            auth_type="NTLM",
            ntlm_strict_mode=False
        )
        with mock.patch("requests_ntlm2.dance.fix_target_info") as mock_fix_target_info:
            mock_fix_target_info.return_value = b"uh-huh!"
            ctx.parse_challenge_message(msg)
            assert ctx._challenge_token != base64.b64decode(msg)
            mock_fix_target_info.assert_called_once_with(base64.b64decode(msg))
            assert ctx._challenge_token == b"uh-huh!"
