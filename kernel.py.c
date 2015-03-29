#if 0
csource = """
#endif
/*
 * shade/kernel.py.c - acecss to kernel interfaces
 */
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

static char module_seed_state[64];

static PyObj
kernel_random(PyObj mod)
{
	return(PyLong_FromLong(random()));
}

static PyObj
kernel_reset(PyObj mod)
{
   initstate(time(NULL), module_seed_state, sizeof(module_seed_state));
   setstate(module_seed_state);

	Py_RETURN_NONE;
}

METHODS() = {
	{"random_integer",
		(PyCFunction) kernel_random, METH_NOARGS,
		PyDoc_STR(
":returns: Random 32-bit integer\n"
"\n"
"Access to kernel's exposed Random function."
)},

	{"_random_seed_reset",
		(PyCFunction) kernel_reset, METH_NOARGS,
		PyDoc_STR(
":returns: None\n"
"\n"
"Reset the seed state."
)},
	{NULL,}
};

INIT(PyDoc_STR("Access to kernel interfaces.\n"))
{
	PyObj mod = NULL;

   initstate(time(NULL), module_seed_state, sizeof(module_seed_state));
   setstate(module_seed_state);

	CREATE_MODULE(&mod);
	if (mod == NULL)
		return(NULL); XCOVERAGE

	return(mod);
error:
	DROP_MODULE(mod);
	return(NULL);
}
/*
 * vim: ts=3:sw=3:noet:
 */
#if 0
"""
#endif
