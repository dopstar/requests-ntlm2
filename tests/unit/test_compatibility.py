from requests_ntlm2.compatibility import NtlmCompatibility


class TestNtlmCompatibility:
    def test_ntlm_compatibility_levels(self):
        assert NtlmCompatibility.LM_AND_NTLMv1 == 0
        assert NtlmCompatibility.LM_AND_NTLMv1_WITH_ESS == 1
        assert NtlmCompatibility.NTLMv1_WITH_ESS == 2
        assert NtlmCompatibility.NTLMv2_DEFAULT == 3
        assert NtlmCompatibility.NTLMv2_LEVEL4 == 4
        assert NtlmCompatibility.NTLMv2_LEVEL5 == 5
