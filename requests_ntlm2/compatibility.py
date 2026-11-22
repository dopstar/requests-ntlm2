"""LAN Manager compatibility levels for NTLM authentication."""


class NtlmCompatibility:
    # see Microsoft doc on compatibility levels here: https://bit.ly/2OWZVxp
    LM_AND_NTLMv1 = 0
    LM_AND_NTLMv1_WITH_ESS = 1
    NTLMv1_WITH_ESS = 2
    NTLMv2_DEFAULT = 3
    NTLMv2_LEVEL4 = 4
    NTLMv2_LEVEL5 = 5
