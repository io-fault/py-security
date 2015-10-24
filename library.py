"""
Primary Access.
"""
try:
	from . import openssl
	implementation = 'OpenSSL'
except ImportError:
	raise ImportError("no available security implementation")
