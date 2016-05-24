from ...development import libfactor
from ...development import libprobe
from ...routes import library as libroutes

parameters = {
	'executable':
		"The openssl executable used to identify headers and library directories.",
}

libfactor.load('system.probe')

import sys
import os.path
import shell_command
import shutil

extract_nids=r"""cat {} | grep 'define[\t ]*NID' | sed 's/#[\t ]*define[ 	]*NID_/OPENSSL_NID(/;s/[ 	]*[0-9]*$/) \\/'"""

def locate_openssl_object_header(executable = 'openssl'):
	"""
	OpenSSL is identified by the presence of the executable 'openssl' in PATH.
	"""
	bin = libroutes.File.which(executable)
	prefix = bin.container.container
	headers = prefix / 'include'
	objh = headers / 'openssl' / 'objects.h'
	return headers, prefix / 'lib', objh

def deploy(probe, module, role):
	headers, libdir, objh = locate_openssl_object_header()
	nid_refs = shell_command.shell_output(extract_nids, str(objh))

	return {
		'preprocessor.defines': [
			("OSSL_NIDS", nid_refs + "\n"),
		],
		'system.library.directories': set([
			
		]),
		'system.include.directories': set([
			headers,
		]),
		'libraries': (
			'ssl',
		)
	}
