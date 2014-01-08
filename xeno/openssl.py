import sys

def probe(context):
	context._dynamic_link(('ssl',))
