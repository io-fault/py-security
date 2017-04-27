"""
# Exception hierarchy for security layer implementations.
"""

class Exception(Exception):
	"""
	# Generic cryptographic exception.
	"""

class Error(Exception):
	"""
	# Ambiguous Error Class.
	"""

class ProtocolError(Error):
	"""
	# A secure transport protocol error.

	# The source information of a protocol error is usually implementation
	# dependent--OpenSSL. However, abstractions may occur in cases of common needs.
	"""

class ContextError(Error):
	"""
	# An context configuration or interface error occurred.

	# Context errors occur when the loading of certificates and keys fails due to formatting
	# error or ambiguous implementation errors are thrown.
	"""

class AllocationError(ContextError):
	"""
	# Error raised when Transports cannot be allocated.
	"""

class KeyError(ContextError):
	"""
	# A key could not be opened--format issues or otherwise; public, private.
	# Details about the issue are implementation dependent.
	"""

class CertificateError(ContextError):
	"""
	# A certificate could not be loaded.
	"""

class InvalidAuthorityError(ContextError):
	"""
	# The authority of a certificate could not be verified.
	"""
