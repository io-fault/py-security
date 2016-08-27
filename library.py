"""
Public APIs.

Provides access to the selected SSL implementation, the default public certificate set,
the host system's certificate set.
"""
import functools
import os

requirement = os.environ.get('TSL_IMPLEMENTATION', None) or None

try:
	from . import openssl as pki
	implementation = 'http://openssl.org'
except ImportError:
	raise ImportError("no available security implementation")

if requirement and requirement != implementation:
	raise ImportError("(system:environment)&TSL_IMPLEMENTATION requirement could not be met")

@functools.lru_cache(2)
def context(*modules):
	"""
	Return a Context instance for the requested set.
	"""
	return pki.Context(certificates=[x.bytes() for x in modules])
