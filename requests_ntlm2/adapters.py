import logging

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.connection import HTTPConnection, HTTPSConnection
from requests.packages.urllib3.poolmanager import pool_classes_by_scheme

from .connection import HTTPConnection as _HTTPConnection
from .connection import HTTPSConnection as _HTTPSConnection


logger = logging.getLogger(__name__)


class HttpNtlmAdapter(HTTPAdapter):
    def __init__(self, ntlm_username, ntlm_password, *args, **kwargs):
        """
        Thin wrapper around requests.adapters.HTTPAdapter
        """
        logger.debug('%s()', self.__class__.__name__)
        self._setup(ntlm_username, ntlm_password)
        super(HttpNtlmAdapter, self).__init__(*args, **kwargs)

    def close(self):
        logger.debug('%s.close()', self.__class__.__name__)
        self._teardown()
        super(HttpNtlmAdapter, self).close()

    @staticmethod
    def _setup(username, password):
        pool_classes_by_scheme['http'].ConnectionCls = _HTTPConnection
        pool_classes_by_scheme['https'].ConnectionCls = _HTTPSConnection
        _HTTPSConnection.set_ntlm_auth_credentials(username, password)

    @staticmethod
    def _teardown():
        pool_classes_by_scheme['http'].ConnectionCls = HTTPConnection
        pool_classes_by_scheme['https'].ConnectionCls = HTTPSConnection
        _HTTPSConnection.clear_ntlm_auth_credentials()
