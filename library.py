"""
Primary Access.
"""
try:
	from .openssl import Context as TLS, State as Transport
	implementation = 'OpenSSL'
except ImportError:
	raise ImportError("no available security implementation")
