from .. import openssl

key = b"""
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAtIW++6LjK5ou4Ej6QLeZInaR0iN7/g5gE5o41Z2QaDA+Xxk9
Weq7jcsdR80gectSnf/lANhl/apD1SjqDDakGUg1iJOnf4VZuPs+iQ/gvUQQpuHp
1CDw/jciRbnrisa7qBFUm1Di8qarqUyQV7GydSu38fX+hYPPoZncCHV6lm81hc5U
nc7oolLGtMw+etT/5bXjJ+Yb0kRrQmOjHwiDQoxWhbgXMr50j3LXXGRfZqp9I7XU
wopeXxPZJHnvZbzmmQuRMnQcrP6eRuPzHTSZtrH6KNUARmLUhoa6LvsYy7+FaWAf
J1KBpu4W2QQ64+Q6wbWDHhzfSduM6bT830oLSwIDAQABAoIBADAhLI8omYqpe+/+
ZQJWMPTYSf6NyWQt7v2q85Y4gSTWH/r43ruXctPWIINhNFRkmi1X6XV1PJQKDjXJ
x8Tj2JKJBwTX4SOFqStBiSW/3vp3KD1mJBKTic0tY+zVKfCBFc00eatDQI7TUxc7
O4y16s+EjXFsVaTBRN1gCSMUN0/d+cyYvPaUhAkL/xVLuwiC0n7m/xvUAf0Kq5gm
3y0QXVcjUM+xxk9HwcrjVJw3qv8xJ5+EXfa7KT0j5BTIwONFaQBGXBOX1TdlKMQ1
uHaPj6Gk70Ee8PC4UpwiC+V0X45ktkCo/+7UNnQ/uhHP3PVmDRod2Fr3lHjJ9s7s
b/zJhQkCgYEA4nzsnjbR26t1L61tb/XkNXYzEVzqKKowxI99Q6SGRjYu4gy4Tvbp
mOQdArvhm99g2MMpJ0x5FJvnMpzYx4mj/H0HBiQVl1UWoT1Kw+h0+0ye6/FungOw
OOUFe2vqyL/ybt/ZW3zbQECZ3iITUrz1fJz+48cP78vJDE3wV10ukPcCgYEAzAuG
kvEZHP/F5ahJdIN6Qz0TD2dW/rNxmY8wKoe3V9LC/QV+zsvwgPgTipYpubbX2WAQ
8PyuQuL3L2Qlk+0tHU4mFtf8QhsVa1r+QMTIq6BvyMiemXicM5JRDpihRXErLt4L
nMx/lnyrXLCkW5l5r+onRLXq97iVKt8WMj5/100CgYAivQ595eKiUtYSjgMvHQP3
vz1t+FZiDliUjX2lFmMR+dWPDmxmkDCcJsDcXnzoL4bnOGfjgzM/GfqIJM6LLG1e
mL6vDnHRWFe0O3ZwPgNTWBk4DzvsOJya3WXN3GuShv5kSylHgwsN+9qd25QjKKBu
kJX30dx750HbBUlL3Rr7WQKBgCYtSeKYZaB9YqOTlxrLtsZ52OUa6rYBERIwLkzm
07EE6CK7Mnyyv68Bu3ZEnk33He+3/7N3M4ukN6eQT0+cIsLG6m1/v90GgD1z6vpn
Vzx1ajThBHumi2NCzxOyDwqVIAVG2lleEckwTkerbTUORCxb3TkH6Iys5ov87YQ9
GWJJAoGAPK2VbRiMd9spgIet89fk2Dq6cYHFyOWnT4ENy2NZMob0iqBIXQEqGly7
L+E+G8rkt2gthud2/nH0jCP6t+qeChSvIMzoDplkyRcUF6pdp9L/ykJNvGJ/kKXs
dbvW+L/0rzP0FqkrMVUKq/+e66sxFZEUylboZM7affAvkvQgZCc=
-----END RSA PRIVATE KEY-----
"""

certificate = b"""
-----BEGIN CERTIFICATE-----
MIIEiDCCA3CgAwIBAgIJAJsRJ/UhSp+eMA0GCSqGSIb3DQEBBQUAMIGIMQswCQYD
VQQGEwJOQTENMAsGA1UECBMETm9uZTENMAsGA1UEBxMEWmVybzERMA8GA1UEChMI
VGVzdCBJbmMxDjAMBgNVBAsTBXRlc3RkMRYwFAYDVQQDEw10ZXN0LmZhdWx0Lmlv
MSAwHgYJKoZIhvcNAQkBFhFjcml0aWNhbEBmYXVsdC5pbzAgFw0xNTA5MjIyMjQ4
MTdaGA8yMjE1MDgwNTIyNDgxN1owgYgxCzAJBgNVBAYTAk5BMQ0wCwYDVQQIEwRO
b25lMQ0wCwYDVQQHEwRaZXJvMREwDwYDVQQKEwhUZXN0IEluYzEOMAwGA1UECxMF
dGVzdGQxFjAUBgNVBAMTDXRlc3QuZmF1bHQuaW8xIDAeBgkqhkiG9w0BCQEWEWNy
aXRpY2FsQGZhdWx0LmlvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
tIW++6LjK5ou4Ej6QLeZInaR0iN7/g5gE5o41Z2QaDA+Xxk9Weq7jcsdR80gectS
nf/lANhl/apD1SjqDDakGUg1iJOnf4VZuPs+iQ/gvUQQpuHp1CDw/jciRbnrisa7
qBFUm1Di8qarqUyQV7GydSu38fX+hYPPoZncCHV6lm81hc5Unc7oolLGtMw+etT/
5bXjJ+Yb0kRrQmOjHwiDQoxWhbgXMr50j3LXXGRfZqp9I7XUwopeXxPZJHnvZbzm
mQuRMnQcrP6eRuPzHTSZtrH6KNUARmLUhoa6LvsYy7+FaWAfJ1KBpu4W2QQ64+Q6
wbWDHhzfSduM6bT830oLSwIDAQABo4HwMIHtMB0GA1UdDgQWBBT/sKif1P6x1gyz
ZAzZZnIqFSQwVzCBvQYDVR0jBIG1MIGygBT/sKif1P6x1gyzZAzZZnIqFSQwV6GB
jqSBizCBiDELMAkGA1UEBhMCTkExDTALBgNVBAgTBE5vbmUxDTALBgNVBAcTBFpl
cm8xETAPBgNVBAoTCFRlc3QgSW5jMQ4wDAYDVQQLEwV0ZXN0ZDEWMBQGA1UEAxMN
dGVzdC5mYXVsdC5pbzEgMB4GCSqGSIb3DQEJARYRY3JpdGljYWxAZmF1bHQuaW+C
CQCbESf1IUqfnjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQBGGVuX
mV8AWKQQHoarWedxDz5icdqQ5aVg67X36EfVwDdwMSewdkMVpCXgNbhCaJzARUBQ
/E3mKwUZRhxk02kDg/Qweb+b9Stq8F5TmEUTUQVCiGttbFj9C6og8lX+V8IMsUIO
3KbNwGpbEyQ2j6K3WA2jAkAzhwpfh1BUuYdfaEqZzbamTfFQ+DP1Yla4jdixmg5G
tnBSV/NMvM0hgm97vTHduTDzGXN3NPsvqksWiTWvft153VCr0Q+kpSsjnNCHvA1g
h+x/clAz7QhLKZomG/FUq9UeRFX5TAb8tp8tq2zK1T9uK6TbFiIcft7mIngiTi0k
TU5G4ur07EfyALq7
-----END CERTIFICATE-----
"""

def test_version(test):
	attributes = [
		'version_code',
		'version_info',
		'version',
		'ciphers',
	]
	m_attributes = dir(openssl)
	for att in attributes:
		test/m_attributes << att

	test.isinstance(openssl.version, str)
	test.isinstance(openssl.version_info, tuple)
	test.isinstance(openssl.version_code, int)
	test.isinstance(openssl.version_info[0], int)
	test.isinstance(openssl.version_info[1], int)
	test.isinstance(openssl.version_info[2], int)

def test_certificate(test):
	crt = openssl.Certificate(certificate)
	test/crt.type == 'x509'

	if 0:
		print(str(crt))
		print(repr(crt))
		print(crt.version)
		print(crt.not_before_string)
		print(crt.not_after_string)
		print(crt.public_key)
		print(crt.subject)

def test_no_certificates(test):
	ctx = openssl.Context()
	test.isinstance(ctx, openssl.Context)
	tls = ctx.connect(None)
	test.isinstance(tls, openssl.Transport)
	tls = ctx.accept()
	test.isinstance(tls, openssl.Transport)
	del tls
	del ctx
	test.garbage(0)

def test_Key_generate_rsa(test):
	k = openssl.Key.generate_rsa(1024)
	if 0:
		print(str(k))
		print(repr(k))
		print(k.type)
	del k
	test.garbage(0)

def test_io(test):
	sctx = openssl.Context(key = key, certificates = [certificate])
	cctx = openssl.Context(certificates = [certificate])

	client = cctx.connect(None)
	server = sctx.accept()

	client_received = []
	server_received = []

	server_send_queue = [b'client message']
	client_send_queue = [b'server message']

	for x in range(4):
		ciphertexts = client.encipher((client_send_queue.pop(0),) if client_send_queue else ())
		plaintexts = server.decipher(ciphertexts)
		server_received.extend(plaintexts)
		ciphertexts = server.encipher((server_send_queue.pop(0),) if server_send_queue else ())
		plaintexts = client.decipher(ciphertexts)
		client_received.extend(plaintexts)

	test/len(server.output_queue) == 0
	test/len(client.output_queue) == 0
	test/b''.join(client_received) == b'client message'
	test/b''.join(server_received) == b'server message'

if __name__ == '__main__':
	import sys; from ...test import library as libtest
	libtest.execute(sys.modules[__name__])
