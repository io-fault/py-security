"""
# Connect an adapter to the stored security context.
"""
import os

from ...system import files
from ...system import process
from ...system import execution

from ...text.bin import ifst
from ...project import library as libproject
from ... import routes

from .. import __file__ as pkgprefix
pkgprefix = files.Path.from_path(pkgprefix).container

project_info = {
	'identifier': "`http://fault.io/python/security/adapter`",
	'name': "`tls-adapter`",
	'controller': "fault.io",
	'versioning': "none",
	'status': "volatile",
	'abstract': "Transport Security Adapter",
	'icon': "- (emoji)`🔒`",
	'contact': "`http://fault.io/critical`"
}

def init_project(route):
	route.init('directory')
	f = route / 'project.txt'
	f.set_text_content(
		"! CONTEXT:\n"
		"\t/protocol/\n"
		"\t\t&<http://if.fault.io/project/information>\n\n" + "\n".join([
			"/%s/\n\t%s" % i for i in project_info.items()
		]) + "\n"
	)
	(route/'extensions').init('directory')

intention = 'debug'
i_headers = libproject.integrals(pkgprefix, routes.Segment.from_sequence(['implementations']))
i_headers += libproject.compose_integral_path({
	'architecture': 'sources',
	'name': 'implementations',
})
i_headers = i_headers.suffix('.' + intention + '.i')

construct_symbols = [
	'security-implementations', '-I'+str(i_headers)
]

def main(inv:process.Invocation) -> process.Exit:
	target, adapter_arg, cctx, *symargs = inv.args # path, *identifiers
	adapter_name, adapter_imp = adapter_arg.split('/')

	cc = files.Path.from_path(cctx) / 'execute'
	route = files.Path.from_path(target) / 'if'
	source = pkgprefix / 'adapters.txt'

	adapter = route / adapter_name
	init_project(adapter)
	factor = adapter / 'extensions' / 'pki'
	ifst.instantiate(factor, source, adapter_name + '-' + adapter_imp)

	ctx_data = factor / 'src' / 'context-data.h'
	ctx_data.set_text_content("#define CONTEXT_LOCATION \"%s\"" % (str(route.container)))

	symbols = ['implementation'] + symargs + construct_symbols
	os.chdir(str(route))
	os.environ['PWD'] = str(route)
	ki = execution.KInvocation(str(cc), [str(cc), 'construct', adapter_name] + symbols)
	pid = ki.spawn({1:1, 2:2}.items())
	os.wait()
