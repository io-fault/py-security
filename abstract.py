"""
Abstract Base Classes and Package Exceptions
"""
import abc

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
