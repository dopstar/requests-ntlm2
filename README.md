<h1 align="center">requests-ntlm2</h1>
<div align="center">NTLM authentication plugin for Requests</div>
<br />

[![Build Status](https://travis-ci.org/dopstar/requests-ntlm2.svg?branch=master)](https://travis-ci.org/dopstar/requests-ntlm2)
[![codecov](https://codecov.io/gh/dopstar/requests-ntlm2/branch/master/graph/badge.svg)](https://codecov.io/gh/dopstar/requests-ntlm2)
[![Python Version](https://img.shields.io/pypi/pyversions/requests-ntlm2.svg)](https://pypi.python.org/pypi/requests-ntlm2)
[![PyPI Status](https://img.shields.io/pypi/v/requests-ntlm2.svg)](https://pypi.python.org/pypi/requests-ntlm2)
[![Downloads](https://img.shields.io/pypi/dm/requests-ntlm2.svg)](https://pypi.python.org/pypi/requests-ntlm2)
[![Licence](https://img.shields.io/github/license/dopstar/requests-ntlm2.svg)](https://raw.githubusercontent.com/dopstar/requests-ntlm2/master/LICENSE)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-101010.svg)](https://github.com/psf/black)

requests-ntlm2, which is based on [requests-ntlm](https://github.com/requests/requests-ntlm), allows for HTTP NTLM authentication using the requests library.

## Installation

```shell
pip install requests-ntlm2
```

## Usage

### Basic Usage
`HttpNtlmAuth` extends requests `AuthBase`, so usage is simple:

```python
import requests
from requests_ntlm2 import HttpNtlmAuth

auth=HttpNtlmAuth('domain\\username','password')
requests.get("http://ntlm_protected_site.com", auth=auth)
```
___

### Changing NTLM compatibility level
See this [MS doc](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc960646%28v=technet.10%29) on LM compatibility levels. `requests_ntlm2` defaults to
compatibility level 3 which supports NTLMv2 [only]. You can change the compatibility level as follows:


```python
import requests
from requests_ntlm2 import HttpNtlmAuth, NtlmCompatibility

username = 'domain\\username'
password = 'password123'
ntlm_compatibility = NtlmCompatibility.LM_AND_NTLMv1_WITH_ESS  # => level 1
auth=HttpNtlmAuth(username, password, ntlm_compatibility=ntlm_compatibility)

requests.get("http://ntlm_protected_site.com", auth=auth)
```
___

### Using with Requests Session
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
___

### HTTP CONNECT Usage
When using `requests-ntlm2` to create SSL proxy tunnel via
[HTTP CONNECT](https://en.wikipedia.org/wiki/HTTP_tunnel#HTTP_CONNECT_method), the so-called
"NTLM Dance" - ie, the NTLM authentication handshake - has to be done at the lower level
(at `httplib` level) at tunnel-creation step. This means that you should use the `HttpNtlmAdapter`
and requests session. This `HttpNtlmAdapter` is responsible for sending proxy auth information
downstream. 

Here is a basic example:

```python
import requests
from requests_ntlm2 import (
    HttpNtlmAuth,
    HttpNtlmAdapter,
    NtlmCompatibility
)

username = '...'
password = '...'
proxy_ip = '...'
proxy_port = '...'

proxies = {
    'http': 'http://{}:{}'.format(proxy_ip, proxy_port),
    'https': 'http://{}:{}'.format(proxy_ip, proxy_port)
}

ntlm_compatibility = NtlmCompatibility.NTLMv2_DEFAULT

session = requests.Session()
session.mount(
    'https://',
    HttpNtlmAdapter(
        username,
        password,
        ntlm_compatibility=ntlm_compatibility
    )
)
session.mount(
    'http://',
    HttpNtlmAdapter(
        username,
        password,
        ntlm_compatibility=ntlm_compatibility
    )
)
session.auth = HttpNtlmAuth(
    username,
    password,
    ntlm_compatibility=ntlm_compatibility
)
session.proxies = proxies

response = session.get('http:/foobar.com')
```

## Requirements

- [requests](https://github.com/kennethreitz/requests/)
- [ntlm-auth](https://github.com/jborean93/ntlm-auth)
