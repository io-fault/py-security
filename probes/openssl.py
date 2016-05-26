from ...development import libfactor
from ...development import libprobe
from ...routes import library as libroutes

_extract_nids=r"""cat {} | grep 'define[\t ]*NID' | sed 's/#[\t ]*define[ 	]*NID_/OPENSSL_NID(/;s/[ 	]*[0-9]*$/) \\/'"""

parameters = {
	'executable':
		"The openssl executable used to identify headers and library directories.",
}

libfactor.load('system.probe')

def locate_openssl_object_header(executable = 'openssl'):
	"""
	OpenSSL is identified by the presence of the executable 'openssl' in PATH.
	"""
	bin = libroutes.File.which(executable)
	prefix = bin.container.container
	headers = prefix / 'include'
	objh = headers / 'openssl' / 'objects.h'
	return headers, prefix / 'lib', objh

data = None

def report(probe, role, module):
	global data
	return data

def deploy(probe, role, module):
	import shell_command

	global data, _extract_nids
	headers, libdir, objh = locate_openssl_object_header()
	nid_refs = shell_command.shell_output(_extract_nids, str(objh))

	data = {
		'preprocessor.defines': [
			("OSSL_NIDS", nid_refs + "\n"),
		],
		'system.library.directories': set([
			
		]),
		'system.include.directories': set([
			headers,
		]),
		'system.library.set': (
			'ssl', 'crypto', 'z',
		)
	}
