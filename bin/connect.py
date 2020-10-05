"""
# Connect an adapter to the stored security context.
"""
import os

from ...system import files
from ...system import process
from ...system import execution

from ...text.bin import ifst
from ...project import root

from .. import __file__ as pkgprefix
pkgprefix = files.Path.from_path(pkgprefix).container

project_info = {
	'authority': "`fault.io`",
	'abstract': "Transport Security Adapter",
	'icon': "- (emoji)`🔒`",
	'contact': "&<http://fault.io/critical>"
}

project_infra = """! CONTEXT:
	/protocol/
		&<http://if.fault.io/project/infrastructure>

/project-c-interfaces/
	- &<http://fault.io/engineering/posix/include>
	- &<http://fault.io/engineering/python/include>
	- &<http://fault.io/python/security/implementations>
"""

def init_product(route, roots):
	pdr = (route/'.product').fs_mkdir()
	(pdr/'ROOTS').set_text_content(' '.join(roots))
	pd = root.Product(route)
	pd.roots = [root.types.factor@x for x in roots]
	return pd

def init_project(product, orientation):
	route = product/orientation
	route.fs_mkdir()

	pi = dict(project_info)
	pi['identifier'] = 'http://fault.io/python/security/kprotocol-' + orientation
	pi['name'] = 'kprotocol-' + orientation

	(route/'.protocol').set_text_content(pi['identifier'] + ' factors/polynomial-1')
	f = route / 'project.txt'
	f.set_text_content(
		"! CONTEXT:\n"
		"\t/protocol/\n"
		"\t\t&<http://if.fault.io/project/information>\n\n" + "\n".join([
			"/%s/\n\t%s" % i for i in pi.items()
		]) + "\n"
	)
	(route/'extensions').fs_mkdir()

	i = route / 'infrastructure.txt'
	i.set_text_content(project_infra)

def main(inv:process.Invocation) -> process.Exit:
	source = pkgprefix / 'adapters.txt'
	target, adapter, implementation, orientation, cctx, *symargs = inv.args

	cc = files.Path.from_path(cctx) / 'execute'
	route = files.Path.from_path(target) / 'if'

	pd = init_product(route/adapter, [orientation])

	init_project(route/adapter, orientation)
	factor = route / adapter / orientation / 'extensions' / 'pki'
	ifst.instantiate(factor, source, '-'.join([adapter, orientation, implementation]))
	pd.update()
	pd.store()

	ctx_data = factor / 'src' / 'context-data.h'
	ctx_data.set_text_content("#define CONTEXT_LOCATION \"%s\"" % (str(route.container)))

	symbols = ['implementation'] + symargs
	ki = (str(cc), [str(cc), 'construct', str(route/adapter), orientation] + symbols)
	pid = execution.KInvocation(*ki).spawn({1:1, 2:2}.items())

	return inv.exit(os.WEXITSTATUS(os.wait()[1]))
