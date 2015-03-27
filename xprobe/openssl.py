import sys
import os.path
import shell_command
import shutil

extract_nids=r"""cat {} | grep 'define NID' | sed 's/#define[ 	]*NID_/OSSL_NID(/' | sed 's/[ 	]*[0-9]*$/) \\/'"""

def locate_openssl_object_header(executable = 'openssl'):
	"""
	OpenSSL is identified by the presence of the executable 'openssl' in PATH.
	"""
	bin = shutil.which(executable)
	prefix = os.path.dirname(os.path.dirname(bin))
	headers = os.path.join(prefix, 'include', 'openssl')
	objh = os.path.join(headers, 'objects.h')
	return objh

def initialize(context):
	objh = locate_openssl_object_header()
	nid_refs = shell_command.shell_output(extract_nids, objh)

	with context as xact:
		context.define_macro(("OSSL_NIDS",), nid_refs + "\n")
		context.dynamic_link('ssl')
