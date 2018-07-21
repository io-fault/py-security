"""
# Extract library directories and include directories for using an OpenSSL installation.
"""
from ...system import library as files
from ...system import library as libsys

_extract_nids = (
	('grep', "define[\t ]*NID"),
	('sed', r"s/#[\t ]*define[ 	]*NID_/OPENSSL_NID(/;s/[ 	]*[0-9]*$/) \\/"),
)

def locate_openssl_object_header(executable):
	bin = files.Path.which(executable)
	prefix = bin.container.container
	headers = prefix / 'include'
	objh = headers / 'openssl' / 'objects.h'
	return headers, prefix / 'lib', objh

def pipe(object_header):
	with object_header.open('rb') as f:
		pipe = libsys.PInvocation.from_commands(*_extract_nids)
