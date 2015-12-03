"""
Abstract Base Classes for Security Implementations
"""
import abc

class Context(metaclass = abc.ABCMeta):
	"""
	The Security Context managing the allocation of secure transport layers for sending
	cipher data over untrusted lines.
	"""

class Transport(metaclass = abc.ABCMeta):
	"""
	The interface to a Secure Transport--an event driven SSL/TLS connection.
	"""
