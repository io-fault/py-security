"""
# OpenSSL bindings for supporting asynchronous I/O.
"""
__factor_domain__ = 'system'
__factor_type__ = 'extension'

from ...probes import openssl # provides environment parameters for openssl
requirements = (
	'python',
)

