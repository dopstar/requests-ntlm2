import logging

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import pool_classes_by_scheme
from .connection import HTTPConnection as _HTTPConnection
from .connection import HTTPSConnection as _HTTPSConnection
from requests.packages.urllib3.connection import (
    HTTPConnection,
    HTTPSConnection,
)


logger = logging.getLogger(__name__)


class HttpNtlmAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        logger.debug('%s()', self.__class__.__name__)
        self._setup()
        super(HttpNtlmAdapter, self).__init__(*args, **kwargs)

    def close(self):
        logger.debug('%s.close()', self.__class__.__name__)
        self._teardown()
        super(HttpNtlmAdapter, self).close()

    @staticmethod
    def _setup():
        pool_classes_by_scheme['http'].ConnectionCls = _HTTPConnection
        pool_classes_by_scheme['https'].ConnectionCls = _HTTPSConnection

    @staticmethod
    def _teardown():
        pool_classes_by_scheme['http'].ConnectionCls = HTTPConnection
        pool_classes_by_scheme['https'].ConnectionCls = HTTPSConnection
