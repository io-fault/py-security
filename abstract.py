"""
Abstract Base Classes and Package Exceptions
"""
import abc

class Exception(Exception):
	"""
	Generic shade exception. Exception instances are rarely raised.
	Often, the dependent software needs to make the decision to raise an exception
	or discard it after inspection.
	"""

class Error(Exception):
	"""
	Ambiguous Error Class.
	"""

class ProtocolError(Error):
	"""
	A secure transport protocol error.

	The source information of a protocol error is usually implementation
	dependent--OpenSSL. However, abstractions may occur in cases of common needs.
	"""

class ContextError(Error):
	"""
	An context configuration or interface error occurred.

	Context errors occur when the loading of certificates and keys fails due to formatting
	error or ambiguous implementation errors are thrown.
	"""

class AllocationError(ContextError):
	"""
	Error raised when Transports cannot be allocated.
	"""

class KeyError(ContextError):
	"""
	A key could not be opened--format issues or otherwise; public, private.
	Details about the issue are implementation dependent.
	"""

class CertificateError(ContextError):
	"""
	A certificate could not be loaded. Normally
	"""

class InvalidAuthorityError(ContextError):
	"""
	The authority of a certificate could not be verified.
	"""

class TLS(metaclass = abc.ABCMeta):
	"""
	The Security Context managing the allocation of secure transport layers for sending
	cipher data over untrusted lines.
	"""

class Transport(metaclass = abc.ABCMeta):
	"""
	The interface to a Secure Transport--an event driven SSL/TLS connection.
	"""

class Transformation(metaclass = abc.ABCMeta):
	"""
	An instance of a transformation. Contains the necessary state for facilitating a
	transformation stream.
	"""

	@abc.abstractmethod
	def transform(self, subject):
		"""
		The method used to perform a transformation with respect the state of the
		transformation instance.
		"""
