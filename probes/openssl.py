"""
Extract library directories and include directories for using an OpenSSL installation.
"""
__factor_type__ = 'system.probe'

from ...development import libprobe
from ...routes import library as libroutes
from ...system import library as libsys

_extract_nids= (
	('grep', "define[\t ]*NID"),
	('sed', r"s/#[\t ]*define[ 	]*NID_/OPENSSL_NID(/;s/[ 	]*[0-9]*$/) \\/"),
)

parameters = {
	'executable':
		"The openssl executable used to identify headers and library directories.",
}

def locate_openssl_object_header(executable):
	"""
	OpenSSL is identified by the presence of the executable 'openssl' in PATH.
	"""
	bin = libroutes.File.which(executable)
	prefix = bin.container.container
	headers = prefix / 'include'
	objh = headers / 'openssl' / 'objects.h'
	return headers, prefix / 'lib', objh

data = None

def deploy(*args, executable='openssl'):
	global data, _extract_nids
	headers, libdir, objh = locate_openssl_object_header(executable)

	if 0:
		with objh.open('rb') as f:
			pipe = libsys.PInvocation.from_commands(*_extract_nids)
	nid_refs = ''

	data = {
		'source.parameters': [
			("OSSL_NIDS", nid_refs),
		],
		'system': {
			'library.directories': set([libdir,]),
			'include.directories': set([headers,]),
			'library.set': ('ssl', 'crypto', 'z',)
		}
	}

	return data

if __name__ == '__main__':
	import pprint
	pprint.pprint(deploy())
