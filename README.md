# requests-ntlm2

[![Build Status](https://travis-ci.org/dopstar/requests-ntlm2.svg?branch=master)](https://travis-ci.org/dopstar/requests-ntlm2)
[![Python Version](https://img.shields.io/pypi/pyversions/requests-ntlm2.svg)](https://pypi.python.org/pypi/requests-ntlm2)
[![PyPI Status](https://img.shields.io/pypi/v/requests-ntlm2.svg)](https://pypi.python.org/pypi/requests-ntlm2)
[![Licence](https://img.shields.io/github/license/dopstar/requests-ntlm2.svg)](https://raw.githubusercontent.com/dopstar/requests-ntlm2/master/LICENSE)

requests-ntlm2, which is based on [requests-ntlm](https://github.com/requests/requests-ntlm) , allows for HTTP NTLM authentication using the requests library.

## Usage

`HttpNtlmAuth` extends requests `AuthBase`, so usage is simple:

```python
import requests
from requests_ntlm2 import HttpNtlmAuth

auth=HttpNtlmAuth('domain\\username','password')
requests.get("http://ntlm_protected_site.com", auth=auth)
```

`HttpNtlmAuth` can be used in conjunction with a `Session` in order to
make use of connection pooling. Since NTLM authenticates connections,
this is more efficient. Otherwise, each request will go through a new
NTLM challenge-response.

```python
import requests
from requests_ntlm2 import HttpNtlmAuth

session = requests.Session()
session.auth = HttpNtlmAuth('domain\\username','password')
session.get('http://ntlm_protected_site.com')
```

## Installation

```shell
pip install requests-ntlm2
```

## Requirements

- [requests](https://github.com/kennethreitz/requests/)
- [ntlm-auth](https://github.com/jborean93/ntlm-auth)
