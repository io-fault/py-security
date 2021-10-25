"""
# Connect an adapter to the stored security context.
"""
import os
import copy

from ...system import files
from ...system import process
from ...system import execution

from ...project import system as lsf
from ...project import factory

info = lsf.types.Information(
	identifier = 'http://fault.io/python/security/kprotocol-',
	name = 'kprotocol-',
	authority = 'fault.io',
	abstract = "Transport Security Adapter",
	icon = dict([('emoji', "🔒")]),
	contact = "&<http://fault.io/critical>"
)

infra = {
	'project-c-interfaces': [
		lsf.types.Reference('http://fault.io/integration/machine', lsf.types.factor@'include'),
		lsf.types.Reference('http://fault.io/integration/python', lsf.types.factor@'include'),
		lsf.types.Reference('http://fault.io/python/security', lsf.types.factor@'implementations'),
	],
	'*.c': [
		lsf.types.Reference('http://if.fault.io/factors',
			lsf.types.factor@'system', 'type', 'c.2011'),
	],
	'*.h': [
		lsf.types.Reference('http://if.fault.io/factors',
			lsf.types.factor@'system', 'type', 'c.header'),
	],
	'*.pyi': [
		lsf.types.Reference('http://if.fault.io/factors',
			lsf.types.factor@'python-interface', 'type', 'v3'),
	],
}

module_template = """
	#define ADAPTER_{upper} 1
	#define ADAPTER_TRANSPORT_NEW transport_new_{lower}
	#define ADAPTER_VERIFY SSL_VERIFY_PEER
	#define CONTEXT_LOCATION "{context}"
	#include <kprotocol-openssl.h>
	#include <fault/python/module.h>

	INIT(module, 0, PyDoc_STR("{lower} kprotocol adapter using OpenSSL."))
	{{
		return(init_implementation_data(module));
	}}
"""

def init_product(route, roots):
	pdr = (route/'.product').fs_mkdir()
	(pdr/'ROOTS').set_text_content(' '.join(roots))
	pd = root.Product(route)
	pd.roots = [lsf.types.factor@x for x in roots]
	pd.update()
	pd.store()
	return pd

def init_project(product, orientation):
	ctxloc = product ** 2 # Stored Security Context location.
	route = product/orientation
	factor = 'extensions.pki'
	syms = ['implementation', 'project-c-interfaces']

	pi = copy.copy(info)
	pi.identifier += orientation
	pi.name += orientation

	srcs = [
		('module.c', module_template.format(
			upper = orientation.upper(),
			lower = orientation,
			context = str(ctxloc),
		)),
	]

	pif = [
		('pki', lsf.types.factor@'python-interface', "# Empty."),
	]
	ext = [
		(factor, 'extension', syms, srcs),
	]

	p = factory.Parameters.define(pi, infra.items(), sets=ext, soles=pif)
	factory.instantiate(p, route)

def main(inv:process.Invocation) -> process.Exit:
	target, adapter, implementation, orientation, intpath, *pdctl = inv.args

	route = files.Path.from_path(target) / 'if'
	init_project(route/adapter, orientation)

	pd = init_product(route/adapter, [orientation])
	cxn = pd.connections_index_route
	cxn.fs_init(intpath.encode('utf-8'))

	if pdctl:
		pdctl, *symargs = pdctl
		symbols = ['implementation'] + symargs
		ki = [pdctl, '-D', str(route/adapter), 'build', orientation] + symbols
		pid = execution.KInvocation(pdctl, ki).spawn({1:1, 2:2}.items())

	return inv.exit(os.WEXITSTATUS(os.wait()[1]))
