"""
# Connect an adapter to the stored security context.
"""
import os
import copy

from ...system import files
from ...system import process
from ...system import execution

from ...text.bin import ifst
from ...project import root
from ...project import factory
from ...project import types

from .. import __file__ as pkgprefix
pkgprefix = files.Path.from_path(pkgprefix).container

info = types.Information(
	identifier = 'http://fault.io/python/security/kprotocol-',
	name = 'kprotocol-',
	authority = 'fault.io',
	abstract = "Transport Security Adapter",
	icon = dict([('emoji', "🔒")]),
	contact = "&<http://fault.io/critical>"
)

infra = {
	'project-c-interfaces': [
		types.Reference('http://fault.io/integration/machine', types.factor@'include'),
		types.Reference('http://fault.io/integration/python', types.factor@'include'),
		types.Reference('http://fault.io/python/security', types.factor@'implementations'),
	],
	'*.c': [
		types.Reference('http://if.fault.io/factors', types.factor@'system', 'type', 'c'),
	],
	'*.h': [
		types.Reference('http://if.fault.io/factors', types.factor@'system', 'type', 'c-header'),
	],
}

def init_product(route, roots):
	pdr = (route/'.product').fs_mkdir()
	(pdr/'ROOTS').set_text_content(' '.join(roots))
	pd = root.Product(route)
	pd.roots = [root.types.factor@x for x in roots]
	pd.update()
	pd.store()
	return pd

def init_project(product, orientation):
	route = product/orientation

	pi = copy.copy(info)
	pi.identifier += orientation
	pi.name += orientation

	p = factory.Parameters.define(pi, infra.items())
	factory.instantiate(p, route)
	(route/'extensions').fs_mkdir()

def main(inv:process.Invocation) -> process.Exit:
	source = pkgprefix / 'adapters.txt'
	target, adapter, implementation, orientation, intpath, *pdctl = inv.args

	route = files.Path.from_path(target) / 'if'

	init_project(route/adapter, orientation)

	factor = route / adapter / orientation / 'extensions' / 'pki'
	ifst.instantiate(factor, source, '-'.join([adapter, orientation, implementation]))

	pd = init_product(route/adapter, [orientation])
	cxn = pd.connections_index_route
	cxn.fs_init(intpath.encode('utf-8'))

	ctx_data = factor / 'src' / 'context-data.h'
	ctx_data.set_text_content("#define CONTEXT_LOCATION \"%s\"" % (str(route.container)))

	if pdctl:
		pdctl, *symargs = pdctl
		symbols = ['implementation'] + symargs
		ki = [pdctl, '-D', str(route/adapter), 'build', orientation] + symbols
		pid = execution.KInvocation(pdctl, ki).spawn({1:1, 2:2}.items())

	return inv.exit(os.WEXITSTATUS(os.wait()[1]))
