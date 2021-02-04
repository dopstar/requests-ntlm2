import base64
import unittest

import faker
import ntlm_auth.ntlm

import requests_ntlm2
import requests_ntlm2.core
import requests_ntlm2.dance


class TestHttpNtlmContext(unittest.TestCase):
    def setUp(self):
        self.fake = faker.Factory.create()

    def test__init(self):
        error_msg = 'Expected "NTLM" or "Negotiate" auth_type, got None'
        with self.assertRaisesRegex(ValueError, error_msg):
            requests_ntlm2.dance.HttpNtlmContext("username", "password")

    def test__init__ntlm(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="NTLM")
        self.assertIsInstance(ctx, requests_ntlm2.dance.HttpNtlmContext)
        self.assertIsInstance(ctx, ntlm_auth.ntlm.NtlmContext)
        self.assertEqual(ctx._auth_type, "NTLM")
        self.assertIsNone(ctx._challenge_token)
        self.assertEqual(ctx.ntlm_compatibility, requests_ntlm2.NtlmCompatibility.NTLMv2_DEFAULT)
        self.assertEqual(ctx.username, username)
        self.assertEqual(ctx.password, password)
        self.assertIsNone(ctx.domain)
        self.assertIsNone(ctx.cbt_data)

    def test__init__negotiate(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="Negotiate")
        self.assertIsInstance(ctx, requests_ntlm2.dance.HttpNtlmContext)
        self.assertIsInstance(ctx, ntlm_auth.ntlm.NtlmContext)
        self.assertEqual(ctx._auth_type, "Negotiate")
        self.assertIsNone(ctx._challenge_token)
        self.assertEqual(ctx.ntlm_compatibility, requests_ntlm2.NtlmCompatibility.NTLMv2_DEFAULT)
        self.assertEqual(ctx.username, username)
        self.assertEqual(ctx.password, password)
        self.assertIsNone(ctx.domain)
        self.assertIsNone(ctx.cbt_data)

    def test_get_negotiate_header(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="NTLM")
        authenticate_header = ctx.get_negotiate_header()
        self.assertEqual(
            authenticate_header,
            "NTLM TlRMTVNTUAABAAAAMYCI4gAAAAAoAAAAAAAAACgAAAAGAbEdAAAADw=="
        )

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
        self.assertTrue(authenticate_header.startswith("NTLM "))
        decoded_authenticate_data = base64.b64decode(authenticate_header.split()[1])
        self.assertEqual(decoded_authenticate_data[:9], b"NTLMSSP\x00\x03")

    def test_set_challenge_from_header(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="NTLM")
        self.assertEqual(ctx._auth_type, "NTLM")

        challenge = (
            "NTLM TlRMTVNTUAACAAAAAAAAAAAAAAAyAojgAnH/LKem1bAAAA"
            "AAAAAAAH4AfgA4AAAABQCTCAAAAA8CAAwARABFAFQATgBTAFcAA"
            "QAaAFMARwAtADAAMgAxADQAMwAwADAAMAAxADUABAAUAEQARQBU"
            "AE4AUwBXAC4AVwBJAE4AAwAwAHMAZwAtADAAMgAxADQAMwAwADAA"
            "MAAxADUALgBkAGUAdABuAHMAdwAuAHcAaQBuAAAAAAA="
        )
        ctx.set_challenge_from_header(challenge)
        self.assertEqual(
            ctx._challenge_token,
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
        self.assertEqual(ctx._auth_type, "NTLM")

        challenge = (
            "WWW-Authenticate: NTLM TlRMTVNTUAACAAAAAAAAAAAAAAAyAojgAnH/LKem1bAAAA"
            "AAAAAAAH4AfgA4AAAABQCTCAAAAA8CAAwARABFAFQATgBTAFcAA"
            "QAaAFMARwAtADAAMgAxADQAMwAwADAAMAAxADUABAAUAEQARQBU"
            "AE4AUwBXAC4AVwBJAE4AAwAwAHMAZwAtADAAMgAxADQAMwAwADAA"
            "MAAxADUALgBkAGUAdABuAHMAdwAuAHcAaQBuAAAAAAA="
        )
        ctx.set_challenge_from_header(challenge)
        self.assertEqual(
            ctx._challenge_token,
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
        self.assertEqual(ctx._auth_type, "NTLM")

        challenge = (
            "Proxy-Authenticate: NTLM TlRMTVNTUAACAAAAAAAAAAAAAAAyAojgAnH/LKem1bAAAA"
            "AAAAAAAH4AfgA4AAAABQCTCAAAAA8CAAwARABFAFQATgBTAFcAA"
            "QAaAFMARwAtADAAMgAxADQAMwAwADAAMAAxADUABAAUAEQARQBU"
            "AE4AUwBXAC4AVwBJAE4AAwAwAHMAZwAtADAAMgAxADQAMwAwADAA"
            "MAAxADUALgBkAGUAdABuAHMAdwAuAHcAaQBuAAAAAAA="
        )
        ctx.set_challenge_from_header(challenge)
        self.assertEqual(
            ctx._challenge_token,
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
        self.assertEqual(ctx._auth_type, "NTLM")

        challenge = (
            "Proxy-Authenticate: NTLM2 TlRMTVNTUAACAAAAAAAAAAAAAAAyAojgAnH/LKem1bAAAA"
            "AAAAAAAH4AfgA4AAAABQCTCAAAAA8CAAwARABFAFQATgBTAFcAA"
            "QAaAFMARwAtADAAMgAxADQAMwAwADAAMAAxADUABAAUAEQARQBU"
            "AE4AUwBXAC4AVwBJAE4AAwAwAHMAZwAtADAAMgAxADQAMwAwADAA"
            "MAAxADUALgBkAGUAdABuAHMAdwAuAHcAaQBuAAAAAAA="
        )
        ctx.set_challenge_from_header(challenge)
        self.assertIsNone(ctx._challenge_token)

    def test_set_challenge_from_header__no_header(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="NTLM")
        self.assertEqual(ctx._auth_type, "NTLM")

        challenge = None
        ctx.set_challenge_from_header(challenge)
        self.assertIsNone(ctx._challenge_token)

    def test_session_security(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="NTLM")
        self.assertIsNone(ctx.session_security)
        self.assertIsNone(ctx._session_security)

        ctx._session_security = self.fake.pystr()
        self.assertIsNotNone(ctx._session_security)
        self.assertEqual(ctx.session_security, ctx._session_security)

        ctx.session_security = None
        self.assertIsNone(ctx.session_security)
        self.assertIsNone(ctx._session_security)

    def test_challenge_message(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="NTLM")
        self.assertIsNone(ctx.challenge_message)
        self.assertIsNone(ctx._challenge_message)

        ctx._challenge_message = self.fake.pystr()
        self.assertIsNotNone(ctx._challenge_message)
        self.assertEqual(ctx.challenge_message, ctx._challenge_message)

        ctx.challenge_message = None
        self.assertIsNone(ctx.challenge_message)
        self.assertIsNone(ctx._challenge_message)

    def test_authenticate_message(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="NTLM")
        self.assertIsNone(ctx.authenticate_message)
        self.assertIsNone(ctx._authenticate_message)

        ctx._authenticate_message = self.fake.pystr()
        self.assertIsNotNone(ctx._authenticate_message)
        self.assertEqual(ctx.authenticate_message, ctx._authenticate_message)

        ctx.authenticate_message = None
        self.assertIsNone(ctx.authenticate_message)
        self.assertIsNone(ctx._authenticate_message)

    def test_negotiate_message(self):
        username = self.fake.user_name()
        password = self.fake.password()
        ctx = requests_ntlm2.dance.HttpNtlmContext(username, password, auth_type="NTLM")
        self.assertIsNone(ctx.negotiate_message)
        self.assertIsNone(ctx._negotiate_message)

        ctx._negotiate_message = self.fake.pystr()
        self.assertIsNotNone(ctx._negotiate_message)
        self.assertEqual(ctx.negotiate_message, ctx._negotiate_message)

        ctx.negotiate_message = None
        self.assertIsNone(ctx.negotiate_message)
        self.assertIsNone(ctx._negotiate_message)
