requests-ntlm
=============

.. image:: https://travis-ci.org/dopstar/requests-ntlm2.svg?branch=master
    :target: https://travis-ci.org/dopstar/requests-ntlm2

.. image:: https://img.shields.io/pypi/pyversions/requests-ntlm2.svg
    :target: https://pypi.python.org/pypi/requests-ntlm2

.. image:: https://img.shields.io/pypi/v/requests-ntlm2.svg
    :target: https://pypi.python.org/pypi/requests-ntlm2

.. image:: https://img.shields.io/github/license/dopstar/requests-ntlm2.svg
    :target: https://raw.githubusercontent.com/dopstar/requests-ntlm2/master/LICENSE

This package allows for HTTP NTLM authentication using the requests library.

Usage
-----

``HttpNtlmAuth`` extends requests ``AuthBase``, so usage is simple:

.. code:: python

    import requests
    from requests_ntlm2 import HttpNtlmAuth

    requests.get("http://ntlm_protected_site.com",auth=HttpNtlmAuth('domain\\username','password'))
    
``HttpNtlmAuth`` can be used in conjunction with a ``Session`` in order to
make use of connection pooling. Since NTLM authenticates connections,
this is more efficient. Otherwise, each request will go through a new
NTLM challenge-response.

.. code:: python

    import requests
    from requests_ntlm2 import HttpNtlmAuth

    session = requests.Session()
    session.auth = HttpNtlmAuth('domain\\username','password')
    session.get('http://ntlm_protected_site.com')

Installation
------------

.. code:: python
    pip install requests-ntlm2

Requirements
------------

- requests_
- ntlm-auth_

.. _requests: https://github.com/kennethreitz/requests/
.. _ntlm-auth: https://github.com/jborean93/ntlm-auth
