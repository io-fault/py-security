"""
# Validate protocol implementations.
"""
from .. import kprotocol as module

class TLS:
	closed = False
	ri = False

	def encipher(self, data):
		return ('secret', data)

	def decipher(self, data):
		return ('reveal', data)

	def close(self):
		self.closed = True

	def receive_interrupt(self):
		self.ri = True

	def connect_transmit_ready(self, cb):
		self.tr = cb

	def connect_receive_closed(self, cb):
		self.rc = cb

def test_allocate(test):
	srx, stx = module.allocate(TLS())

	# Check cross references.
	test/srx.srx_transmit_channel == stx
	test/stx.stx_receive_channel() == srx

def test_transfers(test):
	"""
	# Validate encrypt and decrypt methods.
	"""
	srx, stx = module.allocate(TLS())
	srx.f_emit = (lambda x: x);
	stx.f_emit = (lambda x: x);

	test/srx.f_transfer(b"test") == ('reveal', b"test")
	test/stx.f_transfer(b"test") == ('secret', b"test")

def test_channel_interrupt(test):
	"""
	# - &module.SecuredTransmit.stx_receive_interrupt
	"""
	test.skip("possible change")
	shared = TLS()
	srx, stx = module.allocate(shared)

	srx.exit = (lambda: None)
	stx.exit = (lambda: None)

	srx.f_emit = (lambda x: x)
	stx.f_emit = (lambda x: x)

	test/srx.f_terminate()
	test/stx._stx_receive_closed == True
	test/shared.ri == True

def test_channel_terminate_callback(test):
	"""
	# - &module.SecuredTransmit.stx_receive_closed
	"""
	shared = TLS()
	srx, stx = module.allocate(shared)

	srx.exit = (lambda: None)
	stx.exit = (lambda: None)

	srx.f_emit = (lambda x: x)
	stx.f_emit = (lambda x: x)

	shared.rc()
	test/srx.terminating == True
	test/stx._stx_receive_closed == True

def test_channel_terminate_full(test):
	"""
	# - &module.SecuredTransmit.stx_receive_closed
	"""
	shared = TLS()
	srx, stx = module.allocate(shared)
	termd = set()
	srx._pexe_state = 1
	stx._pexe_state = 1

	srx.exit = (lambda: termd.add(srx))
	stx.exit = (lambda: termd.add(stx))

	srx.f_emit = (lambda x: x)
	stx.f_emit = (lambda x: x)

	stx.f_terminate()
	test/stx.terminating == True
	stx._f_terminated()
	shared.rc()

	test/stx._stx_receive_closed == True
	test/stx.terminated == True
	srx.f_terminate()
	test/srx.terminated == True
	test/shared.closed == True

if __name__ == '__main__':
	pass
