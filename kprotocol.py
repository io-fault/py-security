"""
# &..kernel protocol adapters for transport security contexts.
"""

import weakref
import types
import importlib.machinery

from ..kernel import flows
from ..system import identity
from ..project import library as libproject

def get_application_context(application='http'):
	import os
	from ..system import files

	if 'SECURITY' in os.environ:
		return files.Path.from_absolute(os.environ['SECURITY'])

	return (files.Path.home() / '.pki' / application)

class Violation(Exception):
	def __init__(self, identifier, description):
		self.identifier = identifier
		self.description = description

	def __str__(self):
		return "%s: %s" %(self.identifier, self.description)

def _select(project, intention='debug', name='pki'):
	sys, arch = identity.root_execution_context()
	return libproject.integrals(project, ['extensions', name]).extend(
		libproject.compose_integral_path({
			'system': sys,
			'architecture': arch,
			'name': name,
		})
	).suffix('.' + intention + '.i')

def load_context(route, type:str, name='pki'):
	project = route / 'if' / ('kprotocol-' + type)
	dllpath = _select(project, name=name)
	loader = importlib.machinery.ExtensionFileLoader(name, str(dllpath))
	return loader.load_module()

def load(type:str, application='http', name='pki'):
	route = get_application_context(application)
	return load_context(route, type, name=name)

class SecuredTransmit(flows.Protocol):
	"""
	# Transport stack entry for secured output.
	# Holds a weak reference to the corresponding &SecuredReceive instance
	# using &stx_receive_channel.
	"""

	_stx_receive_closed = False

	def stx_receive_closed(self):
		"""
		# Signal endpoint recognizing when the corresponding receive
		# has seen a transport protocol level termination.
		"""
		self._stx_receive_closed = True

		if self.terminating:
			self._f_terminated()

	def stx_receive_interrupt(self):
		"""
		# Wire closed without protocol shutdown.
		"""
		self._stx_receive_closed = True

		if self.terminating:
			self._f_terminated()

	def f_terminate(self):
		if not self.functioning:
			return

		self.start_termination()

		if self.p_shared.close():
			self.p_drain()

class SecuredReceive(flows.Protocol):
	"""
	# Transport stack entry for secured input.
	# Holds a strong reference to the corresponding &SecuredTransmit instance
	# using &srx_transmit_channel.
	"""

	def p_terminated(self):
		self.start_termination()
		self.srx_transmit_channel.stx_receive_closed()

	def f_terminate(self):
		if not self.terminating:
			self.srx_transmit_channel.stx_receive_interrupt()
		self._f_terminated()

def allocate(tls, Method=weakref.WeakMethod, Reference=weakref.ref):
	"""
	# Construct a protocol stack pair using the given &tls instance.
	"""

	stx = SecuredTransmit(tls, None, tls.encipher)
	srx = SecuredReceive(tls, None, tls.decipher)

	srx.srx_transmit_channel = stx
	stx.stx_receive_channel = Reference(srx)

	drain = Method(stx.p_drain)
	tls.connect_transmit_ready((lambda: drain()()))

	ptermd = Method(srx.p_terminated)
	tls.connect_receive_closed((lambda: ptermd()()))

	return (srx, stx)
