#include <kprotocol-openssl.h>

#include <fault/python/module.h>
INIT(module, 0, PyDoc_STR("kprotocol adapter for OpenSSL."))
{
	return(init_implementation_data(module));
}
