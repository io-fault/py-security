"""
Public APIs.

Provides access to the selected SSL implementation, the default public certificate set,
the host system's certificate set.
"""
import functools
import os

implementation_requirement = os.environ.get('SSL_IMPLEMENTATION', 'OpenSSL')

try:
	from . import openssl as pki
	implementation = 'OpenSSL'
except ImportError:
	raise ImportError("no available security implementation")

if implementation_requirement != implementation:
	raise ImportError("&/unix/env/SSL_IMPLEMENTATION requirement could not be met")

@functools.lru_cache(2)
def context(*modules):
	"""
	Return a Context instance for the requested set.
	"""
	return pki.Context(certificates=[x.bytes() for x in modules])
