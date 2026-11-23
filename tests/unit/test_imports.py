import subprocess
import sys

import pytest


@pytest.mark.parametrize(
    "module, excluded",
    [
        ("requests_ntlm2", ("requests", "ntlm_auth", "cryptography", "requests_ntlm2.")),
        ("requests_ntlm2.constants", ("requests", "ntlm_auth", "cryptography")),
        ("requests_ntlm2.auth", ("requests_ntlm2.proxy",)),
        (
            "requests_ntlm2.proxy.adapters.base",
            ("ntlm_auth", "requests_ntlm2.auth", "requests_ntlm2.proxy.connection",
             "requests_ntlm2.proxy.adapters.ntlm"),
        ),
        (
            "requests_ntlm2.proxy.adapters.ntlm",
            ("requests_ntlm2.auth", "requests_ntlm2._channel_binding"),
        ),
    ],
)
def test_imports_load_only_needed_modules(module, excluded):
    script = """
import importlib
import sys

before = set(sys.modules)
importlib.import_module(sys.argv[1])
loaded = set(sys.modules) - before
for prefix in sys.argv[2:]:
    if prefix.endswith("."):
        matches = {name for name in loaded if name.startswith(prefix)}
    else:
        matches = {name for name in loaded if name == prefix or name.startswith(prefix + ".")}
    assert not matches, sorted(matches)
"""
    subprocess.check_call([sys.executable, "-c", script, module, *excluded])
