"""
# Initialize a stored security context on the filesystem.
"""
from ...system import process
from ...system import files

def init(route):
	route.init('directory')
	adapters = (route/'if')
	adapters.init('directory')

def main(inv:process.Invocation) -> process.Exit:
	path, = inv.args # target path to initialize
	route = files.Path.from_path(path)
	init(route)
