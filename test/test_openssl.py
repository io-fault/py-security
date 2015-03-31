from .. import openssl

def test_version(test):
	test/True == ('version_code' in dir(openssl))
	test/True == ('version_info' in dir(openssl))
	test/True == ('version' in dir(openssl))
	# potentially implementation dependent
	test/True == ('ciphers' in dir(openssl))

	test/openssl.version / str
	test/openssl.version_info / tuple
	test/openssl.version_code / int

	test/openssl.version_info[0] / int
	test/openssl.version_info[1] / int
	test/openssl.version_info[2] / int

def test_certificate(test):
	from ..fault import pki
	fio = pki.certificate()
	crt = openssl.Certificate(fio)
	print(str(crt))
	print(repr(crt))
	print(crt.version)
	print(crt.not_before_string)
	print(crt.not_after_string)
	print(crt.public_key)
	print(crt.subject)

def test_no_certificates(test):
	ctx = openssl.Context()
	test/ctx / openssl.Context
	tls = ctx.rallocate()
	test/tls / openssl.Transport
	tls = ctx.rallocate()
	test/tls / openssl.Transport
	del tls
	del ctx
	test.garbage(0)

def test_io(test):
	return
	from ..fault import pki

	fio = pki.certificate('fault.io')
	k = None
	with open('/x/io.fault.key', mode='rb') as f:
		k = f.read()

	sctx = openssl.Context(key = k, certificates = [fio])
	cctx = openssl.Context(certificates = [fio])

	client = cctx.rallocate()
	server = sctx.rallocate()

	b = bytearray(2048)
	q = client.read_enciphered(b)
	server.write_enciphered(b[:q])

	b = bytearray(2048)
	q = server.read_enciphered(b)
	client.write_enciphered(b[:q])

	b = bytearray(2048)
	q = client.read_enciphered(b)
	server.write_enciphered(b[:q])

	b = bytearray(2048)
	q = server.read_enciphered(b)
	client.write_enciphered(b[:q])

	server.write_deciphered(b'foo')
	client.write_deciphered(b'bar')

	b = bytearray(2048)
	q = client.read_enciphered(b)
	server.write_enciphered(b[:q])

	b = bytearray(2048)
	q = server.read_enciphered(b)
	client.write_enciphered(b[:q])

	test/client.pending_enciphered_writes == 0
	test/client.pending_enciphered_reads == 0
	test/server.pending_enciphered_writes == 0
	test/server.pending_enciphered_reads == 0

	print(server.protocol)

	b = bytearray(1024)
	test/b[:server.read_deciphered(b)] == b'bar'
	test/b[:client.read_deciphered(b)] == b'foo'

if __name__ == '__main__':
	import sys; from ...development import libtest
	libtest.execute(sys.modules[__name__])
