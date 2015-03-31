from .. import library

def test_feature(test):
	test/'foo' == 'foo'

if __name__ == '__main__':
	import sys; from ...development import libtest
	libtest.execute(sys.modules[__name__])
