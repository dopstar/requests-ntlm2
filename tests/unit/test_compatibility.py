from requests_ntlm2.compatibility import NtlmCompatibility as LegacyNtlmCompatibility
from requests_ntlm2.constants import NtlmCompatibility


def test_legacy_import_returns_the_same_class():
    assert LegacyNtlmCompatibility is NtlmCompatibility
