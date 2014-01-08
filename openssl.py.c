#if 0
csource = """
#endif
/*
 * shade/openssl.py.c - openssl access
 */
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <openssl/opensslv.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <openssl/x509.h>
#include <openssl/pem.h>

#define GetPointer(pb) (pb.buf)
#define GetSize(pb) (pb.len)

typedef enum {
	state_protocol_error = -3,		/* effectively shutdown */
	state_remote_shutdown = -2,	/* shutdown from remote */
	state_has_shutdown = -1,		/* shutdown from local request */
	state_not_shutdown = 0,
	state_init_shutdown = 1,
} shutdown_t;

static PyObj version_info = NULL, version_str = NULL;

/*
 * Security Context [Cipher/Protocol Parameters]
 */
typedef SSL_CTX *context_t;

/*
 * TLS [Connection] State
 */
typedef SSL *state_t;

/*
 * TLS parameter for keeping state with memory instead of sockets.
 */
typedef struct {
	BIO *ossl_breads;
	BIO *ossl_bwrites;
} memory_t;

struct Context {
	PyObject_HEAD
	context_t tls_context;
};
typedef struct Context *Context;

struct State {
	PyObject_HEAD
	Context ctx_object;

	state_t tls_state;
	memory_t tls_memory;

	shutdown_t tls_shutdown_state;
	PyObj tls_protocol_error; /* dictionary or NULL (None) */

	/*
	 * These are updated when I/O of any sort occurs and
	 * provides a source for event signalling.
	 */
	unsigned long tls_pending_reads, tls_pending_writes;
};
typedef struct State *State;

static PyTypeObject ContextType, StateType;

static PyObj
context_repr(PyObj self)
{
	Context ctx = (Context) self;
	PyObj rob;

	rob = PyUnicode_FromFormat("<%s %p>", Py_TYPE(ctx)->tp_name, ctx);
	return(rob);
}

static State
create_tls_state(PyTypeObject *typ, Context ctx)
{
	State tls;

	tls = (State) typ->tp_alloc(typ, 0);
	if (tls == NULL)
		return(NULL); XCOVERAGE

	/* XXX: type check */
	tls->ctx_object = ctx;
	Py_INCREF(((PyObj) ctx));

	/* XXX: error checking */
	tls->tls_state = SSL_new(ctx->tls_context);

	/*
	 * I/O buffers for the connection.
	 */
	tls->tls_memory.ossl_breads = BIO_new(BIO_s_mem());
	tls->tls_memory.ossl_bwrites = BIO_new(BIO_s_mem());

	SSL_set_bio(tls->tls_state, tls->tls_memory.ossl_breads, tls->tls_memory.ossl_bwrites);

	return(tls);
}

static int
update_io_sizes(State tls)
{
	char *ignored;
	int changes = 0;
	long size;

	size = BIO_get_mem_data(tls->tls_memory.ossl_breads, &ignored);
	if (size != tls->tls_pending_reads)
	{
		tls->tls_pending_reads = size;
		changes |= 1 << 0;
	}

	size = BIO_get_mem_data(tls->tls_memory.ossl_bwrites, &ignored);
	if (size != tls->tls_pending_writes)
	{
		tls->tls_pending_writes = size;
		changes |= 1 << 1;
	}

	return(changes);
}

/*
 * OpenSSL uses a per-thread error queue.
 */
static PyObj
pop_protocol_error(void)
{
	PyObj rob;
	int line = -1, flags = 0;
	const char *lib, *func, *reason, *path, *data = NULL;
	unsigned long error_code;

	error_code = ERR_get_error_line_data(&path, &line, &data, &flags);

	lib = ERR_lib_error_string(error_code);
	func = ERR_func_error_string(error_code);
	reason = ERR_reason_error_string(error_code);

	if (lib[0] == '\0')
		lib = NULL;

	if (func[0] == '\0')
		func = NULL;

	if (reason[0] == '\0')
		reason = NULL;

	if (data[0] == '\0')
		data = NULL;

	if (path[0] == '\0')
		path = NULL;

	rob = Py_BuildValue(
		"{s:k,s:s,s:s,s:s,s:s,s:s,s:i}",
			"code", error_code,
			"library", lib,
			"function", func,
			"reason", reason,
			"data", data,
			"path", path,
			"line", line
	);

	if (flags & ERR_TXT_MALLOCED && data != NULL)
		free(data);

	return(rob);
}

/*
 * Update the error status of the State object.
 * Flip state bits if necessary.
 */
static void
check_result(State tls, int result)
{
	switch(result)
	{
		/*
		 * Expose the needs of the TLS state?
		 * XXX: pending size checks may cover this.
		 */
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_NONE:
		break;

		case SSL_ERROR_ZERO_RETURN:
			/*
			 * Terminated.
			 */
			switch (tls->tls_shutdown_state)
			{
				case state_init_shutdown:
					tls->tls_shutdown_state = state_has_shutdown;
				break;

				case state_not_shutdown:
					/*
					 * Zero returns indicate shutdown
					 */
					tls->tls_shutdown_state = state_remote_shutdown;
				break;

				default:
					/*
					 * Already configured shutdown state.
					 */
				break;
			}
		break;

		case SSL_ERROR_SSL:
		{
			tls->tls_protocol_error = pop_protocol_error();
			tls->tls_shutdown_state = state_protocol_error;
		}
		break;

		case SSL_ERROR_WANT_X509_LOOKUP:
			/*
			 * XXX: Currently, no callback can be set.
			 */
		case SSL_ERROR_WANT_CONNECT:
		case SSL_ERROR_WANT_ACCEPT:
		case SSL_ERROR_SYSCALL:
			/*
			 * Not applicable to this implementation (memory BIO's).
			 *
			 * This should probably cause an exception and is likely
			 * a programming error in OpenSSL or a hardware/platform error.
			 */
		default:
			printf("unknown result code: %d\n", result);
		break;
	}
}

/*
 * context_connect() - create a new state object using the security context
 */
static PyObj
context_connect(PyObj self)
{
	Context ctx = (Context) self;
	State tls;

	tls = create_tls_state(&StateType, ctx);
	SSL_set_connect_state(tls->tls_state);

	/*
	 * Get TLS state started with a zero-length write. (WANT_READ)
	 */
	check_result(tls, SSL_get_error(tls->tls_state, SSL_do_handshake(tls->tls_state)));

	return((PyObj) tls);
}

/*
 * context_accept() - create a new state object using the security context
 */
static PyObj
context_accept(PyObj self)
{
	Context ctx = (Context) self;
	State tls;

	tls = create_tls_state(&StateType, ctx);
	SSL_set_accept_state(tls->tls_state);

	/*
	 * Get TLS state started with a zero-length write. (WANT_READ)
	 */
	check_result(tls, SSL_get_error(tls->tls_state, SSL_do_handshake(tls->tls_state)));

	return((PyObj) tls);
}

static PyMethodDef
context_methods[] = {
	{"connect", (PyCFunction) context_connect,
		METH_NOARGS, PyDoc_STR(
"connect()\n\n"
"Create a TLS :py:class:`State` instance for use with a client connection."
"\n"
)},

	{"accept", (PyCFunction) context_accept,
		METH_NOARGS, PyDoc_STR(
"accept()\n\n"
"Create a TLS :py:class:`State` instance for use with a server connection."
"\n"
)},

	{NULL,},
};

static PyMemberDef
context_members[] = {
	{NULL,},
};

static void
context_dealloc(PyObj self)
{
	Context ctx = (Context) self;
	SSL_CTX_free(ctx->tls_context);
}

static PyObj
context_new(PyTypeObject *subtype, PyObj args, PyObj kw)
{
	static char *kwlist[] = {
		"method", "ciphers", "allow_ssl_version_two",
		NULL,
	};
	char *method = "compat";
	char *ciphers = "NULL";
	int allow_ssl_v2 = 0;
	Context ctx;

	if (!PyArg_ParseTupleAndKeywords(args, kw,
		"|ssp", kwlist,
		&method,
		&ciphers,
		&allow_ssl_v2
	))
		return(NULL); XCOVERAGE

	ctx = (Context) subtype->tp_alloc(subtype, 0);
	if (ctx == NULL)
		return(NULL); XCOVERAGE

	if (strcmp(method, "TLS-1.2") == 0)
	{
		ctx->tls_context = SSL_CTX_new(TLSv1_2_method());
	}
	else if (strcmp(method, "TLS-1.1") == 0)
	{
		ctx->tls_context = SSL_CTX_new(TLSv1_1_method());
	}
	else if (strcmp(method, "TLS-1.0") == 0)
	{
		ctx->tls_context = SSL_CTX_new(TLSv1_method());
	}
	else
	{
		ctx->tls_context = SSL_CTX_new(SSLv23_method());
	}

	if (allow_ssl_v2)
	{
		/*
		 * Require exlicit override to allow this.
		 */
		SSL_CTX_set_options(ctx->tls_context, SSL_OP_NO_SSLv2);
	}

	SSL_CTX_set_cipher_list(ctx->tls_context, ciphers);

	return((PyObj) ctx);
}

PyDoc_STRVAR(context_doc,
"OpenSSL security context objects");

static PyTypeObject
ContextType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	QPATH("Context"),				/* tp_name */
	sizeof(struct Context),		/* tp_basicsize */
	0,									/* tp_itemsize */
	context_dealloc,				/* tp_dealloc */
	NULL,								/* tp_print */
	NULL,								/* tp_getattr */
	NULL,								/* tp_setattr */
	NULL,								/* tp_compare */
	context_repr,					/* tp_repr */
	NULL,								/* tp_as_number */
	NULL,								/* tp_as_sequence */
	NULL,								/* tp_as_mapping */
	NULL,								/* tp_hash */
	NULL,								/* tp_call */
	NULL,								/* tp_str */
	NULL,								/* tp_getattro */
	NULL,								/* tp_setattro */
	NULL,								/* tp_as_buffer */
	Py_TPFLAGS_BASETYPE|
	Py_TPFLAGS_DEFAULT,			/* tp_flags */
	context_doc,					/* tp_doc */
	NULL,								/* tp_traverse */
	NULL,								/* tp_clear */
	NULL,								/* tp_richcompare */
	0,									/* tp_weaklistoffset */
	NULL,								/* tp_iter */
	NULL,								/* tp_iternext */
	context_methods,				/* tp_methods */
	context_members,				/* tp_members */
	NULL,								/* tp_getset */
	NULL,								/* tp_base */
	NULL,								/* tp_dict */
	NULL,								/* tp_descr_get */
	NULL,								/* tp_descr_set */
	0,									/* tp_dictoffset */
	NULL,								/* tp_init */
	NULL,								/* tp_alloc */
	context_new,					/* tp_new */
};

static const char *
shutdown_state_string(shutdown_t i)
{
	switch (i)
	{
		case state_protocol_error:
			return "error";
		break;

		case state_remote_shutdown:
			return "remote";
		break;

		case state_has_shutdown:
			return "local";
		break;

		case state_init_shutdown:
			return "init";
		break;

		case state_not_shutdown:
			return NULL;
		break;
	}
}

/*
 * state_status() - extract the status of the TLS connection
 */
static PyObj
state_status(PyObj self)
{
	State tls = (State) self;
	PyObj rob;

	rob = Py_BuildValue("(siss)",
		shutdown_state_string(tls->tls_shutdown_state),
		SSL_state(tls->tls_state),
		SSL_state_string(tls->tls_state),
		SSL_state_string_long(tls->tls_state)
	);

	return(rob);
}

/*
 * Place enciphered data to be decrypted and read by the local endpoint.
 */
static PyObj
state_read_enciphered(PyObj self, PyObj buffer)
{
	State tls = (State) self;
	Py_buffer pb;
	int xfer;

	if (PyObject_GetBuffer(buffer, &pb, PyBUF_WRITABLE))
		return(NULL); XCOVERAGE

	/*
	 * XXX: Low memory situations may cause partial transfers
	 */
	xfer = BIO_read(tls->tls_memory.ossl_bwrites, GetPointer(pb), GetSize(pb));
	PyBuffer_Release(&pb);

	if (xfer < 0 && GetSize(pb) > 0)
	{
		PyErr_SetString(PyExc_MemoryError, "failed to read from enciphered data buffer");
		return(NULL);
	}
	update_io_sizes(tls);

	return(PyLong_FromLong((long) xfer));
}

static PyObj
state_write_enciphered(PyObj self, PyObj buffer)
{
	char peek[sizeof(int)];
	State tls = (State) self;
	Py_buffer pb;
	int xfer;

	if (PyObject_GetBuffer(buffer, &pb, PyBUF_WRITABLE))
		return(NULL); XCOVERAGE

	/*
	 * XXX: Low memory situations may cause partial transfers
	 */
	xfer = BIO_write(tls->tls_memory.ossl_breads, GetPointer(pb), GetSize(pb));
	PyBuffer_Release(&pb);

	if (xfer < 0 && GetSize(pb) > 0)
	{
		/*
		 * Ignore BIO_write errors in cases where the buffer size is zero.
		 */
		PyErr_SetString(PyExc_MemoryError, "failed to write into enciphered data buffer");
		return(NULL);
	}
	else
	{
		int dxfer = 0;
		/*
		 * Is there a deciphered byte available?
		 */
		dxfer = SSL_peek(tls->tls_state, peek, 1);
		if (dxfer > 0)
			peek[0] = 0;
		else
		{
			check_result(tls, SSL_get_error(tls->tls_state, dxfer));
		}
	}

	update_io_sizes(tls);

	return(PyLong_FromLong((long) xfer));
}

static PyObj
state_read_deciphered(PyObj self, PyObj buffer)
{
	State tls = (State) self;
	Py_buffer pb;
	int xfer;

	if (PyObject_GetBuffer(buffer, &pb, PyBUF_WRITABLE))
		return(NULL); XCOVERAGE

	xfer = SSL_read(tls->tls_state, GetPointer(pb), GetSize(pb));
	if (xfer < 1)
	{
		check_result(tls, SSL_get_error(tls->tls_state, xfer));
		xfer = 0;
	}
	update_io_sizes(tls);

	PyBuffer_Release(&pb);

	return(PyLong_FromLong((long) xfer));
}

static PyObj
state_write_deciphered(PyObj self, PyObj buffer)
{
	State tls = (State) self;
	Py_buffer pb;
	int xfer;

	if (PyObject_GetBuffer(buffer, &pb, 0))
		return(NULL); XCOVERAGE

	xfer = SSL_write(tls->tls_state, GetPointer(pb), GetSize(pb));
	if (xfer < 1)
	{
		check_result(tls, SSL_get_error(tls->tls_state, xfer));
		xfer = 0;
	}
	update_io_sizes(tls);

	PyBuffer_Release(&pb);

	return(PyLong_FromLong((long) xfer));
}

static PyObj
state_shutdown(PyObj self)
{
	State tls = (State) self;

	if (tls->tls_shutdown_state != 0)
	{
		Py_INCREF(Py_False);
		return(Py_False); /* signals that shutdown seq was already initiated or done */
	}

	SSL_shutdown(tls->tls_state);
	update_io_sizes(tls);

	Py_INCREF(Py_True);
	return(Py_True); /* signals that shutdown has been initiated */
}

static PyMethodDef
state_methods[] = {
	{"status", (PyCFunction) state_status,
		METH_NOARGS, PyDoc_STR(
"status()\n\n"
"\n"
)},
	{"shutdown", (PyCFunction) state_shutdown,
		METH_NOARGS, PyDoc_STR(
"shutdown()\n\n"
"\n"
)},

	{"read_enciphered", (PyCFunction) state_read_enciphered,
		METH_O, PyDoc_STR(
"read_enciphered(buffer)\n\n"
"Get enciphered data to be written to the remote endpoint. Transfer to be written."
"\n"
)},
	{"write_enciphered", (PyCFunction) state_write_enciphered,
		METH_O, PyDoc_STR(
"write_enciphered()\n\n"
"Put enciphered data into the TLS channel to be later decrypted and retrieved with read_deciphered."
"\n"
)},

	{"read_deciphered", (PyCFunction) state_read_deciphered,
		METH_O, PyDoc_STR(
"read_deciphered()\n\n"
"Get decrypted data from the TLS channel for processing by the local endpoint."
"\n"
)},
	{"write_deciphered", (PyCFunction) state_write_deciphered,
		METH_O, PyDoc_STR(
"write_deciphered(buffer)\n\n"
"Put decrypted data into the TLS channel to be sent to the remote endpoint after encryption."
"\n"
)},

	{NULL,},
};

static PyMemberDef
state_members[] = {
	{"error", T_OBJECT, offsetof(struct State, tls_protocol_error), READONLY,
		PyDoc_STR("Protocol error data. :py:obj:`None` if no *protocol* error occurred.")},
	{"pending_enciphered_writes", T_ULONG, offsetof(struct State, tls_pending_writes), READONLY,
		PyDoc_STR("Snapshot of the TLS state's out-going buffer used for writing. Growth indicates need for lower-level write.")},
	{"pending_enciphered_reads", T_ULONG, offsetof(struct State, tls_pending_reads), READONLY,
		PyDoc_STR("Snapshot of the TLS state's incoming buffer used for reading. Growth indicates need for higher-level read attempt.")},
	{NULL,},
};

static PyObj
state_repr(PyObj self)
{
	State tls = (State) self;
	PyObj rob;
	rob = PyUnicode_FromFormat("<%s %p[%s]>", Py_TYPE(self)->tp_name, self, SSL_state_string(tls->tls_state));
	return(rob);
}

static void
state_dealloc(PyObj self)
{
	State tls = (State) self;
	SSL_free(tls->tls_state);
}

static PyObj
state_new(PyTypeObject *subtype, PyObj args, PyObj kw)
{
	static char *kwlist[] = {"context", NULL,};
	Context ctx = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "O", kwlist, &ctx))
		return(NULL); XCOVERAGE

	return((PyObj) create_tls_state(subtype, ctx));
}

PyDoc_STRVAR(state_doc,
"OpenSSL security context objects");

static PyTypeObject
StateType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	QPATH("State"),				/* tp_name */
	sizeof(struct State),		/* tp_basicsize */
	0,									/* tp_itemsize */
	state_dealloc,					/* tp_dealloc */
	NULL,								/* tp_print */
	NULL,								/* tp_getattr */
	NULL,								/* tp_setattr */
	NULL,								/* tp_compare */
	state_repr,						/* tp_repr */
	NULL,								/* tp_as_number */
	NULL,								/* tp_as_sequence */
	NULL,								/* tp_as_mapping */
	NULL,								/* tp_hash */
	NULL,								/* tp_call */
	NULL,								/* tp_str */
	NULL,								/* tp_getattro */
	NULL,								/* tp_setattro */
	NULL,								/* tp_as_buffer */
	Py_TPFLAGS_BASETYPE|
	Py_TPFLAGS_DEFAULT,			/* tp_flags */
	state_doc,						/* tp_doc */
	NULL,								/* tp_traverse */
	NULL,								/* tp_clear */
	NULL,								/* tp_richcompare */
	0,									/* tp_weaklistoffset */
	NULL,								/* tp_iter */
	NULL,								/* tp_iternext */
	state_methods,					/* tp_methods */
	state_members,					/* tp_members */
	NULL,								/* tp_getset */
	NULL,								/* tp_base */
	NULL,								/* tp_dict */
	NULL,								/* tp_descr_get */
	NULL,								/* tp_descr_set */
	0,									/* tp_dictoffset */
	NULL,								/* tp_init */
	NULL,								/* tp_alloc */
	state_new,						/* tp_new */
};

static PyObj
nulls(PyObj mod, PyObj arg)
{
	Py_RETURN_NONE;
}

METHODS() = {
	{"nulls",
		(PyCFunction) nulls, METH_O,
		PyDoc_STR(
":returns: \n"
"\n"
"doc."
)},
	{NULL,}
};

#define PYTHON_TYPES() \
	ID(Context) \
	ID(State)

INIT(PyDoc_STR("OpenSSL\n"))
{
	PyObj ob;
	PyObj mod = NULL;

	/*
	 * Initialize OpenSSL.
	 */
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	SSL_library_init();

	CREATE_MODULE(&mod);
	if (mod == NULL)
		return(NULL); XCOVERAGE

	if (PyModule_AddStringConstant(mod, "implementation", "OpenSSL"))
		goto error;

	if (PyModule_AddIntConstant(mod, "version_code", OPENSSL_VERSION_NUMBER))
		goto error;

	if (PyModule_AddStringConstant(mod, "version", OPENSSL_VERSION_TEXT))
		goto error;

	/*
	 * Break up the version into sys.version_info style tuple.
	 *
	 * 0x1000105fL is 1.0.1e final
	 */
	{
		int patch_code = ((OPENSSL_VERSION_NUMBER >> 4) & 0xFF);
		int status_code = (OPENSSL_VERSION_NUMBER & 0xF);
		char *status = NULL, *patch = NULL, patch_char[2];

		switch (status_code)
		{
			case 0:
				status = "dev";
			break;

			case 0xF:
				status = "final";
			break;

			default:
				status = "beta";
			break;
		}

		switch (patch_code)
		{
			case 0:
				patch = NULL;
			break;
			default:
				patch_code += (int) 'a';
				patch_char[0] = patch_code - 1;
				patch_char[1] = '\0';
				patch = patch_char;
			break;
		}

		version_info = Py_BuildValue("(iiiss)",
			(OPENSSL_VERSION_NUMBER >> 28) & 0xFF,
			(OPENSSL_VERSION_NUMBER >> 20) & 0xFF,
			(OPENSSL_VERSION_NUMBER >> 12) & 0xFF,
			patch, status
		);

		if (PyModule_AddObject(mod, "version_info", version_info))
			goto error;
	}

	/*
	 * Initialize Transit types.
	 */
#define ID(NAME) \
	if (PyType_Ready((PyTypeObject *) &( NAME##Type ))) \
		goto error; \
	if (PyModule_AddObject(mod, #NAME, (PyObj) &( NAME##Type )) < 0) \
		goto error;
	PYTHON_TYPES()
#undef ID

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
