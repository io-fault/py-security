"""
# Public APIs.

# Provides access to the selected SSL implementation, the default public certificate set,
# the host system's certificate set.

# [ Engineering ]
# /Future/
	# - Signature interfaces for generation and verficiation.
"""
import functools
import os

requirement = os.environ.get('TLS_IMPLEMENTATION', None) or None

# Only one TLS module, but leave the frame for requirement checks.
try:
	from . import openssl as pki
	implementation = 'http://openssl.org'
except ImportError:
	pass

if requirement and requirement != implementation:
	raise ImportError("(system/environ)`TLS_IMPLEMENTATION` requirement could not be met")

@functools.lru_cache(2)
def context(*modules):
	"""
	# Return a Context instance for the requested set.
	"""
	return pki.Context(certificates=[x.bytes() for x in modules])
