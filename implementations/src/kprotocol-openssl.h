/**
	// SSL_CTX_set_client_cert_cb()
	// SSL_ERROR_WANT_X509_LOOKUP (SSL_get_error return)

	// The OpenSSL folks note a significant limitation of this feature as
	// that the callback functions cannot return a full chain. However,
	// if the chain is pre-configured on the Context, the full chain will be sent.
	// The current implementation of OpenSSL means that a callback selecting
	// the exact chain is... limited.

	// X509_NAMES = SSL_get_client_CA_list(transport_t) - client connection get server (requirements) CA list.
*/
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <openssl/opensslv.h>

#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#include <openssl/objects.h>

#ifdef OPENSSL_NO_EVP
	#error fault.security transport context requires openssl with EVP
#endif

#ifndef FAULT_OPENSSL_CIPHERS
	#define FAULT_OPENSSL_CIPHERS "RC4:HIGH:!aNULL:!eNULL:!NULL:!MD5"
#endif

#include <fault/libc.h>
#include <fault/python/environ.h>

#define Transport_GetReadBuffer(tls) (SSL_get_rbio(tls->tls_state))
#define Transport_GetWriteBuffer(tls) (SSL_get_wbio(tls->tls_state))

/*
	// Python Memory Buffers
*/
#define GetPointer(pb) (pb.buf)
#define GetSize(pb) (pb.len)

/**
	// Call codes used to identify the library function that caused an error.
*/
typedef enum {
	call_none = 0,
	call_handshake,
	call_read,
	call_write,
	call_close,   /* terminate */
	call_connect, /* set connect */
	call_accept,  /* set accept */
	call_shutdown,
	call_set_hostname,
} call_t;

static const char *
library_call_string(call_t call)
{
	const char *r;

	switch (call)
	{
		case call_none:
			r = "none";
		break;

		case call_set_hostname:
			r = "SSL_set_tlsext_host_name";
		break;

		case call_handshake:
			r = "SSL_do_handshake";
		break;

		case call_read:
			r = "SSL_read";
		break;

		case call_write:
			r = "SSL_write";
		break;

		case call_close:
			r = "SSL_shutdown";
		break;

		case call_shutdown:
			r = "SSL_shutdown";
		break;

		default:
			r = "<unknown call identifier>";
		break;
	}

	return(r);
}

/**
	// Security Context [Cipher/Protocol Parameters]
*/
typedef SSL_CTX *context_t;
#define free_context_t SSL_CTX_free

/**
	// An instance of TLS for facilitating a secure connection.
*/
typedef SSL *transport_t;
#define free_transport_t SSL_free

/**
	// An X509 Certificate.
*/
typedef X509 *certificate_t;
#define free_certificate_t X509_free

/**
	// Public or Private Key
*/
typedef EVP_PKEY *pki_key_t;

typedef enum {
	tls_protocol_error = -3,     /* effectively terminated */
	tls_remote_termination = -2, /* shutdown from remote */
	tls_local_termination = -1,  /* shutdown initiated locally */
	tls_not_terminated = 0,
	tls_terminating = 1,
} termination_t;

typedef enum {
	key_none,
	key_required,
	key_available
} key_status_t;

static PyObj version_info = NULL, version_str = NULL;

/**
	// Key object structure.
*/
struct Key {
	PyObject_HEAD
	pki_key_t lib_key;
};
typedef struct Key *Key;

/**
	// Certificate object structure.
*/
struct Certificate {
	PyObject_HEAD
	certificate_t lib_crt;
};
typedef struct Certificate *Certificate;

/**
	// Security context object structure.
*/
struct Context {
	PyObject_HEAD
	context_t tls_context;
	key_status_t tls_key_status;
};
typedef struct Context *Context;

#define output_buffer_extend(tls, x) PyObject_CallMethod(tls->output_queue, "extend", "(O)", x)
#define output_buffer_append(tls, x) PyObject_CallMethod(tls->output_queue, "append", "O", x)
#define output_buffer_has_content(tls) PyObject_IsTrue(tls->output_queue)
#define output_buffer_initial(tls) PySequence_GetItem(tls->output_queue, 0)
#define output_buffer_pop(tls) PySequence_DelItem(tls->output_queue, 0)

/**
	// TLS connection state.
*/
struct Transport {
	PyObject_HEAD
	Context ctx_object;

	transport_t tls_state;

	PyObj tls_protocol_error; /* dictionary or NULL (None) */

	/**
		// NULL until inspected then cached until the Transport is terminated.
	*/
	PyObj tls_peer_certificate;
	PyObj output_queue; /* when SSL_write is not possible */
	PyObj recv_closed_cb;
	PyObj send_queued_cb;

	termination_t tls_termination;
	signed char tls_terminate; /* side being terminated. */
};
typedef struct Transport *Transport;

static PyObj Queue; /* write queue type; collections.deque */
static PyTypeObject KeyType, CertificateType, ContextType, TransportType;

/**
	// Prompting is rather inappropriate from a library;
	// this callback is used throughout the source to manage
	// the encryption key of a certificate or private key.
*/
struct password_parameter {
	char *words;
	Py_ssize_t length;
};

/**
	// Callback used to parameterize the password.
*/
static int
password_parameter(char *buf, int size, int rwflag, void *u)
{
	struct password_parameter *pwp = u;

	strncpy(buf, pwp->words, (size_t) size);
	buf[size] = '\0';
	return((int) pwp->length);
}

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
	/**
		// TLS methods were changed in 1.1.
	*/
	#define X_TLS_METHODS() X_TLS_METHOD("TLS", TLS)
	#define X_TLS_PROTOCOLS() \
		X_TLS_PROTOCOL(ietf.org, RFC, 0, TLS,  0, 0, TLS)
#else
	#ifndef OPENSSL_NO_SSL3_METHOD
		#define _X_TLS_METHOD_SSLv3 X_TLS_METHOD("SSL-3.0", SSLv3)
	#else
		#define _X_TLS_METHOD_SSLv3
	#endif

	/*
		// OpenSSL V < 1.1 doesn't provide us with an X-Macro of any sort, so hand add as needed.
		// Might have to rely on some probes at some point... =\

		// ORG, TYPE, ID, NAME, VERSION, OPENSSL_FRAGMENT
	*/
	#define X_TLS_PROTOCOLS() \
		X_TLS_PROTOCOL(ietf.org, RFC, 2246, TLS,  1, 0, TLSv1)   \
		X_TLS_PROTOCOL(ietf.org, RFC, 4346, TLS,  1, 1, TLSv1_1) \
		X_TLS_PROTOCOL(ietf.org, RFC, 5246, TLS,  1, 2, TLSv1_2) \
		X_TLS_PROTOCOL(ietf.org, RFC, 6101, SSL,  3, 0, SSLv23)

	/*
		// X_TLS_PROTOCOL(ietf.org, RFC, 8446, TLS,  1, 3, TLSv1_3) \
	*/

	#define X_TLS_METHODS()               \
		X_TLS_METHOD("TLS", TLSv1_2)      \
		X_TLS_METHOD("TLS-1.0", TLSv1)    \
		X_TLS_METHOD("TLS-1.1", TLSv1_1)  \
		X_TLS_METHOD("TLS-1.2", TLSv1_2)  \
		_X_TLS_METHOD_SSLv3 \
		X_TLS_METHOD("compat",  SSLv23)
#endif

#define X_CERTIFICATE_TYPES() \
	X_CERTIFICATE_TYPE(ietf.org, RFC, 5280, X509)

/**
	// TODO
	// Context Cipher List Specification
	// Context Certificate Loading
	// Context Certificate Loading
*/
#define X_TLS_ALGORITHMS() \
	X_TLS_ALGORITHMS(RSA)  \
	X_TLS_ALGORITHMS(DSA)  \
	X_TLS_ALGORITHMS(DH)

#define X_CA_EVENTS()        \
	X_CA_EVENT(CSR, REQUEST) \
	X_CA_EVENT(CRL, REVOKE)

/**
	// Function Set to load Security Elements.
*/
#define X_READ_OPENSSL_OBJECT(TYP, LOCAL_SYM, OPENSSL_CALL) \
static TYP \
LOCAL_SYM(PyObj buf, pem_password_cb *cb, void *cb_data) \
{ \
	Py_buffer pb; \
	TYP element = NULL; \
	BIO *bio; \
	\
	if (PyObject_GetBuffer(buf, &pb, 0)) \
		return(NULL); \
	\
	/* Implicit Read-Only BIO: Py_buffer data is directly referenced. */ \
	bio = BIO_new_mem_buf(GetPointer(pb), GetSize(pb)); \
	if (bio == NULL) \
	{ \
		PyErr_SetString(PyExc_MemoryError, "could not allocate OpenSSL memory for security object"); \
	} \
	else \
	{ \
		element = OPENSSL_CALL(bio, NULL, cb, cb_data); \
		BIO_free(bio); \
	} \
	\
	PyBuffer_Release(&pb); \
	return(element); \
}

/**
	// need a small abstraction
*/
X_READ_OPENSSL_OBJECT(certificate_t, load_pem_certificate, PEM_read_bio_X509)
X_READ_OPENSSL_OBJECT(pki_key_t, load_pem_private_key, PEM_read_bio_PrivateKey)
X_READ_OPENSSL_OBJECT(pki_key_t, load_pem_public_key, PEM_read_bio_PUBKEY)
#undef X_READ_OPENSSL_OBJECT

/**
	// OpenSSL uses a per-thread error queue, but
	// there is storage space on Transport for explicit association.
*/
static PyObj
pop_openssl_error(call_t call)
{
	PyObj rob;
	int line = -1, flags = 0;
	const char *lib, *func, *reason, *path, *data = NULL, *ldata;
	unsigned long error_code;

	error_code = ERR_get_error_line_data(&path, &line, &data, &flags);

	lib = ERR_lib_error_string(error_code);
	func = ERR_func_error_string(error_code);
	reason = ERR_reason_error_string(error_code);

	if (lib && lib[0] == '\0')
		lib = NULL;

	if (func && func[0] == '\0')
		func = NULL;

	if (reason && reason[0] == '\0')
		reason = NULL;

	if (data && data[0] == '\0')
		ldata = NULL;
	else
		ldata = data;

	if (path && path[0] == '\0')
		path = NULL;

	rob = Py_BuildValue(
		"((sk)(ss)(ss)(ss)(ss)(ss)(si))",
			"code", error_code,
			"library", lib,
			"function", func,
			"reason", reason,
			"data", ldata,
			"path", path,
			"line", line,
			"call", library_call_string(call)
	);

	ERR_clear_error();
	return(rob);
}

/**
	// Used for objects other than Transports.
	// XXX: core removed recently; create local exception?
*/
static void
set_openssl_error(const char *exc_name, call_t call)
{
	PyObj err, exc = PyImport_ImportAdjacent("kprotocol", exc_name);
	if (exc == NULL)
		return;

	if (ERR_peek_error() == 0)
		return;

	err = pop_openssl_error(call);
	PyErr_SetObject(exc, err);
}

static PyObj
key_generate_rsa(PyTypeObject *subtype, PyObj args, PyObj kw)
{
	static char *kwlist[] = {
		"bits",
		"engine",
		NULL
	};
	unsigned long bits = 2048;

	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	Key k;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "|ks", kwlist, &bits))
		return(NULL);

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (ctx == NULL)
	{
		goto lib_error;
	}

	if (EVP_PKEY_keygen_init(ctx) <= 0)
	{
		goto lib_error;
	}

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
	{
		goto lib_error;
	}

	if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
	{
		goto lib_error;
	}

	EVP_PKEY_CTX_free(ctx);
	ctx = NULL;

	k = (Key) subtype->tp_alloc(subtype, 0);
	if (k == NULL)
	{
		return(NULL);
	}
	else
	{
		k->lib_key = pkey;
	}

	return((PyObj) k);

	lib_error:
	{
		if (ctx != NULL)
			EVP_PKEY_CTX_free(ctx);

		set_openssl_error("Error", 0);
		return(NULL);
	}
}

static PyObj
key_encrypt(PyObj self, PyObj data)
{
	Py_RETURN_NONE;
}

static PyObj
key_decrypt(PyObj self, PyObj data)
{
	Py_RETURN_NONE;
}

static PyObj
key_sign(PyObj self, PyObj data)
{
	/* Private Key */
	Py_RETURN_NONE;
}

static PyObj
key_verify(PyObj self, PyObj data)
{
	/* Public Key */
	Py_RETURN_NONE;
}

static PyMethodDef
key_methods[] = {
	{"generate_rsa", (PyCFunction) key_generate_rsa,
		METH_CLASS|METH_VARARGS|METH_KEYWORDS, PyDoc_STR(
			"Generate an Key [Usually a pair]."
		)
	},

	{"encrypt", (PyCFunction) key_encrypt,
		METH_O, PyDoc_STR(
			"Encrypt the given binary data."
		)
	},

	{"decrypt", (PyCFunction) key_decrypt,
		METH_O, PyDoc_STR(
			"Decrypt the given binary data."
		)
	},

	{"sign", (PyCFunction) key_sign,
		METH_O, PyDoc_STR(
			"Sign the given binary data."
		)
	},

	{"verify", (PyCFunction) key_verify,
		METH_VARARGS, PyDoc_STR(
			"Verify the signature of the binary data."
		)
	},

	{NULL,},
};

static const char *
key_type_string(Key k)
{
	switch (EVP_PKEY_base_id(k->lib_key))
	{
		case EVP_PKEY_RSA:
			return "rsa";
		break;

		case EVP_PKEY_DSA:
			return "dsa";
		break;

		case EVP_PKEY_DH:
			return "dh";
		break;

		case EVP_PKEY_EC:
			return "ec";
		break;
	}

	return "unknown";
}

static PyObj
key_get_type(PyObj self, void *p)
{
	Key k = (Key) self;

	return(PyUnicode_FromString(key_type_string(k)));
}

static PyGetSetDef
key_getset[] = {
	{"type",
		key_get_type, NULL,
		PyDoc_STR("certificate type; always X509."),
	},

	{NULL,},
};

static void
key_dealloc(PyObj self)
{
	Key k = (Key) self;
	EVP_PKEY_free(k->lib_key);
}

static PyObj
key_repr(PyObj self)
{
	PyObj rob;
	Key k = (Key) self;

	rob = PyUnicode_FromFormat("<openssl.Key[%s] %p>", key_type_string(k), k);
	return(rob);
}

static PyObj
key_str(PyObj self)
{
	Key k = (Key) self;
	PyObj rob = NULL;
	BIO *out;
	char *ptr = NULL;
	Py_ssize_t size = 0;

	out = BIO_new(BIO_s_mem());
	if (out == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "could not allocate memory BIO for Key");
		return(NULL);
	}

	if (EVP_PKEY_print_public(out, k->lib_key, 0, NULL) <= 0)
		goto error;
	if (EVP_PKEY_print_private(out, k->lib_key, 0, NULL) <= 0)
		goto error;
	if (EVP_PKEY_print_params(out, k->lib_key, 0, NULL) <= 0)
		goto error;

	size = (Py_ssize_t) BIO_get_mem_data(out, &ptr);
	rob = Py_BuildValue("s#", ptr, size);

	BIO_free(out);

	return(rob);

	error:
	{
		set_openssl_error("Error", 0);

		BIO_free(out);
		return(NULL);
	}
}

static PyObj
key_new(PyTypeObject *subtype, PyObj args, PyObj kw)
{
	static char *kwlist[] = {"pem", NULL,};
	PyObj pem;
	Key k;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "O", kwlist, &pem))
		return(NULL);

	k = (Key) subtype->tp_alloc(subtype, 0);
	if (k == NULL)
		return(NULL);

	Py_RETURN_NONE;

	lib_error:
		set_openssl_error("Error", 0);
	fail:
		Py_XDECREF(k);
		return(NULL);
}

PyDoc_STRVAR(key_doc, "OpenSSL EVP_PKEY objects.");

static PyTypeObject
KeyType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	PYTHON_MODULE_PATH("Key"),      /* tp_name */
	sizeof(struct Key),             /* tp_basicsize */
	0,                              /* tp_itemsize */
	key_dealloc,                    /* tp_dealloc */
	NULL,                           /* tp_print */
	NULL,                           /* tp_getattr */
	NULL,                           /* tp_setattr */
	NULL,                           /* tp_compare */
	key_repr,                       /* tp_repr */
	NULL,                           /* tp_as_number */
	NULL,                           /* tp_as_sequence */
	NULL,                           /* tp_as_mapping */
	NULL,                           /* tp_hash */
	NULL,                           /* tp_call */
	key_str,                        /* tp_str */
	NULL,                           /* tp_getattro */
	NULL,                           /* tp_setattro */
	NULL,                           /* tp_as_buffer */
	Py_TPFLAGS_BASETYPE|
	Py_TPFLAGS_DEFAULT,             /* tp_flags */
	key_doc,                        /* tp_doc */
	NULL,                           /* tp_traverse */
	NULL,                           /* tp_clear */
	NULL,                           /* tp_richcompare */
	0,                              /* tp_weaklistoffset */
	NULL,                           /* tp_iter */
	NULL,                           /* tp_iternext */
	key_methods,                    /* tp_methods */
	NULL,                           /* tp_members */
	key_getset,                     /* tp_getset */
	NULL,                           /* tp_base */
	NULL,                           /* tp_dict */
	NULL,                           /* tp_descr_get */
	NULL,                           /* tp_descr_set */
	0,                              /* tp_dictoffset */
	NULL,                           /* tp_init */
	NULL,                           /* tp_alloc */
	key_new,                        /* tp_new */
};

/**
	// primary &transport_new parts. Normally called by the Context methods.
*/
static Transport
create_tls_state(PyTypeObject *typ, Context ctx)
{
	const static char *mem_err_str = "could not allocate memory BIO for secure Transport";
	Transport tls;
	BIO *rb, *wb;

	tls = (Transport) typ->tp_alloc(typ, 0);
	if (tls == NULL)
		return(NULL);

	tls->recv_closed_cb = NULL;
	tls->send_queued_cb = NULL;

	tls->output_queue = PyObject_CallFunctionObjArgs(Queue, NULL);
	if (tls->output_queue == NULL)
	{
		Py_DECREF(tls);
		return(NULL);
	}

	tls->ctx_object = ctx;

	tls->tls_state = SSL_new(ctx->tls_context);
	if (tls->tls_state == NULL)
	{
		set_openssl_error("Error", 0);
		Py_DECREF(tls);
		return(tls);
	}

	Py_INCREF(((PyObj) ctx));

	/**
		// I/O buffers for the connection.
		// Unlike SSL_new error handling, be noisy about memory errors.
	*/
	rb = BIO_new(BIO_s_mem());
	wb = BIO_new(BIO_s_mem());

	if (rb == NULL || wb == NULL)
	{
		if (rb)
			BIO_free(rb);
		if (wb)
			BIO_free(wb);

		PyErr_SetString(PyExc_MemoryError, mem_err_str);
		goto fail;
	}

	BIO_set_mem_eof_return(rb, -1);
	BIO_set_mem_eof_return(wb, -1);

	SSL_set_bio(tls->tls_state, rb, wb);

	return(tls);

	fail:
	{
		Py_DECREF(tls);
		return(NULL);
	}
}

/**
	// Assigned error data.
	// Transports are used for asynchonous purposes and success
	// with an exception is a possible state, so the error has to be
	// assigned and then raised after the transfer has been performed.
*/
static int
transport_library_error(Transport subject, call_t call)
{
	if (ERR_peek_error())
	{
		subject->tls_protocol_error = pop_openssl_error(call);
		subject->tls_termination = tls_protocol_error;
		return(-1);
	}

	return(0);
}

/**
	// Raised exception.
*/
static int
library_error(const char *errclass, call_t call)
{
	if (ERR_peek_error())
	{
		set_openssl_error(errclass, call);
		return(-1);
	}
	else
		return(0);
}

/**
	// Loading certificates from an iterator is common, so
	// a utility macro. Would be a function, but some load ops are macros.
*/
#define CERT_INIT_LOOP(NAME, INITIAL, SUBSEQUENT) \
static int NAME(context_t ctx, PyObj certificates) \
{ \
	PyObj ob, pi; \
	\
	pi = PyObject_GetIter(certificates); \
	if (pi == NULL) \
		return(0); \
	\
	ob = PyIter_Next(pi); \
	if (PyErr_Occurred()) \
		goto py_fail; \
	\
	if (ob != NULL) \
	{ \
		certificate_t cert; \
		\
		cert = load_pem_certificate(ob, NULL, NULL); \
		Py_DECREF(ob); \
		\
		if (cert == NULL) \
		{ \
			if (PyErr_Occurred()) \
				goto py_fail; \
			else \
				goto lib_fail; \
		} \
		\
		if (!INITIAL(ctx, cert)) \
			goto lib_fail; \
		\
		while ((ob = PyIter_Next(pi))) \
		{ \
			if (PyErr_Occurred()) \
				goto py_fail; \
			\
			cert = load_pem_certificate(ob, NULL, NULL); \
			Py_DECREF(ob); \
			\
			if (cert == NULL) \
				goto lib_fail; \
			if (!SUBSEQUENT(ctx, cert)) \
				goto lib_fail; \
		} \
	} \
	\
	Py_DECREF(pi); \
	return(1); \
	\
	lib_fail: \
		library_error("Error", 0); \
	py_fail: \
		Py_DECREF(pi); \
		return(0); \
}

CERT_INIT_LOOP(load_certificate_chain, SSL_CTX_use_certificate, SSL_CTX_add_extra_chain_cert)
CERT_INIT_LOOP(load_client_requirements, SSL_CTX_add_client_CA, SSL_CTX_add_client_CA)

static PyObj
certificate_open(PyTypeObject *subtype, PyObj args, PyObj kw)
{
	static char *kwlist[] = {
		"path",
		"password",
		NULL
	};

	struct password_parameter pwp = {"", 0};
	char *path = NULL;
	FILE *fp = NULL;
	Certificate cert;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "s|s#", kwlist, &path, &(pwp.words), &(pwp.length)))
		return(NULL);

	cert = (Certificate) subtype->tp_alloc(subtype, 0);
	if (cert == NULL)
		return(NULL);

	fp = fopen(path, "rb");
	if (fp == NULL)
	{
		PyErr_SetFromErrno(PyExc_OSError);
		Py_DECREF(cert);
		return(NULL);
	}

	cert->lib_crt = PEM_read_X509(fp, NULL, password_parameter, &pwp);
	if (cert->lib_crt == NULL)
		goto lib_error;

	return((PyObj) cert);

	lib_error:
		set_openssl_error("Error", 0);
	fail:
	{
		Py_DECREF(cert);
		return(NULL);
	}
}

static PyMethodDef
certificate_methods[] = {
	{"open", (PyCFunction) certificate_open,
		METH_CLASS|METH_VARARGS|METH_KEYWORDS, PyDoc_STR(
			"Read a certificate directly from the filesystem.\n"
		)
	},

	{NULL,},
};

static PyMemberDef
certificate_members[] = {
	{NULL,},
};

/*
	X509_REQ_get_version
	X509_REQ_get_subject_name
	X509_REQ_extract_key
*/
/*
	X509_CRL_get_version(x)
	X509_CRL_get_lastUpdate(x)
	X509_CRL_get_nextUpdate(x)
	X509_CRL_get_issuer(x)
	X509_CRL_get_REVOKED(x)
*/

static PyObj
key_from_lib_key(EVP_PKEY *k)
{
	Py_RETURN_NONE;
}

static PyObj
str_from_asn1_string(ASN1_STRING *str)
{
	PyObj rob;
	unsigned char *utf = NULL;
	int len = 0;

	len = ASN1_STRING_to_UTF8(&utf, str);
	rob = PyUnicode_FromStringAndSize((const char *) utf, len);

	OPENSSL_free(utf);

	return(rob);
}

static PyObj
seq_from_names(X509_NAME *n)
{
	X509_NAME_ENTRY *item;

	PyObj rob;
	int i = 0, count;

	rob = PyList_New(0);
	if (rob == NULL)
		return(NULL);

	count = X509_NAME_entry_count(n);
	while (i < count)
	{
		PyObj val, robi = NULL;
		ASN1_OBJECT *iob;
		int nid;
		const char *name;

		item = X509_NAME_get_entry(n, i);
		iob = X509_NAME_ENTRY_get_object(item);

		val = str_from_asn1_string(X509_NAME_ENTRY_get_data(item));
		if (val == NULL)
		{
			Py_DECREF(rob);
			return(NULL);
		}

		nid = OBJ_obj2nid(iob);
		name = OBJ_nid2ln(nid);

		robi = Py_BuildValue("(sO)", name, val);

		if (robi == NULL || PyList_Append(rob, robi))
		{
			Py_DECREF(rob);
			return(NULL);
		}

		++i;
	}

	return(rob);
}

static PyObj
str_from_asn1_time(ASN1_TIME *t)
{
	PyObj rob;
	ASN1_GENERALIZEDTIME *gt;

	/*
		// The other variants are strings as well...
		// The UTCTIME strings omit the century and
		// millennium parts of the year.
	*/

	#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
		gt = ASN1_TIME_to_generalizedtime(t, NULL);
	#else
		gt = ASN1_TIME_to_generalizedtime(t, NULL);
		rob = PyUnicode_FromStringAndSize((const char *) M_ASN1_STRING_data(gt), M_ASN1_STRING_length(gt));
		M_ASN1_GENERALIZEDTIME_free(gt);
	#endif

	return(rob);
}

static PyObj
str_from_nid(int n)
{
	return(PyUnicode_FromString(OBJ_nid2ln(n)));
}

static PyObj
long_from_asn1_integer(ASN1_INTEGER *i)
{
	return(PyLong_FromLong(ASN1_INTEGER_get(i)));
}

#define CERTIFICATE_PROPERTIES() \
	CERT_PROPERTY(not_before_string, \
		"The 'notBefore' field as a string.", X509_get_notBefore, str_from_asn1_time) \
	CERT_PROPERTY(not_after_string, \
		"The 'notAfter' field as a string.", X509_get_notAfter, str_from_asn1_time) \
	CERT_PROPERTY(signature_type, \
		"The type of signature used to sign the key.", X509_get_signature_type, str_from_nid) \
	CERT_PROPERTY(key, \
		"The public key provided by the certificate.", X509_get_pubkey, key_from_lib_key) \
	CERT_PROPERTY(subject, \
		"The subject data of the cerficate.", X509_get_subject_name, seq_from_names) \
	CERT_PROPERTY(issuer, \
		"The issuer data of the cerficate.", X509_get_issuer_name, seq_from_names) \
	CERT_PROPERTY(version, \
		"The Format Version", X509_get_version, PyLong_FromLong) \
	CERT_PROPERTY(serial, \
		"The serial number field", X509_get_serialNumber, long_from_asn1_integer)

#define CERT_PROPERTY(NAME, DOC, GET, CONVERT) \
	static PyObj certificate_get_##NAME(PyObj crt, void *p) \
	{ \
		certificate_t lib_crt = ((Certificate) crt)->lib_crt; \
		return(CONVERT(GET(lib_crt))); \
	} \

	CERTIFICATE_PROPERTIES()
#undef CERT_PROPERTY

static PyObj
certificate_get_type(PyObj self, void *p)
{
	return (PyUnicode_FromString("x509"));
}

static PyGetSetDef certificate_getset[] = {
	#define CERT_PROPERTY(NAME, DOC, UNUSED1, UNUSED2) \
		{#NAME, certificate_get_##NAME, NULL, PyDoc_STR(DOC)},

		CERTIFICATE_PROPERTIES()
	#undef CERT_PROPERTY

	{"type",
		certificate_get_type, NULL,
		PyDoc_STR("certificate type; always X509."),
	},
	{NULL,},
};

static void
certificate_dealloc(PyObj self)
{
	Certificate cert = (Certificate) self;
	X509_free(cert->lib_crt);
}

static PyObj
certificate_repr(PyObj self)
{
	Certificate cert = (Certificate) self;
	PyObj rob, sn_ob;
	BIO *b;
	char *ptr;
	long size;
	X509_NAME *sn;

	sn = X509_get_subject_name(cert->lib_crt);

	b = BIO_new(BIO_s_mem());

	X509_NAME_print(b, sn, 0);

	size = BIO_get_mem_data(b, &ptr);

	sn_ob = Py_BuildValue("s#", ptr, size);
	rob = PyUnicode_FromFormat("<%s [%U] %p>", Py_TYPE(cert)->tp_name, sn_ob, cert);

	BIO_free(b);

	return(rob);
}

static PyObj
certificate_str(PyObj self)
{
	Certificate cert = (Certificate) self;
	PyObj rob;
	BIO *b;
	char *ptr;
	long size;

	b = BIO_new(BIO_s_mem());
	X509_print(b, cert->lib_crt);

	size = BIO_get_mem_data(b, &ptr);

	rob = Py_BuildValue("s#", ptr, size);

	BIO_free(b);

	return(rob);
}

static PyObj
certificate_new(PyTypeObject *subtype, PyObj args, PyObj kw)
{
	static char *kwlist[] = {
		"pem",
		"password",
		NULL,
	};
	struct password_parameter pwp = {"", 0};

	PyObj pem;
	Certificate cert;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "O|s#", kwlist,
			&pem,
			&(pwp.words), &(pwp.length)
		))
		return(NULL);

	cert = (Certificate) subtype->tp_alloc(subtype, 0);
	if (cert == NULL)
	{
		return(NULL);
	}

	cert->lib_crt = load_pem_certificate(pem, password_parameter, &pwp);
	if (cert->lib_crt == NULL)
		goto lib_error;

	return((PyObj) cert);

	lib_error:
		set_openssl_error("Error", 0);
	fail:
		Py_XDECREF(cert);
		return(NULL);
}

PyDoc_STRVAR(certificate_doc, "OpenSSL X509 Certificate Objects");

static PyTypeObject
CertificateType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	PYTHON_MODULE_PATH("Certificate"), /* tp_name */
	sizeof(struct Certificate),        /* tp_basicsize */
	0,                                 /* tp_itemsize */
	certificate_dealloc,               /* tp_dealloc */
	NULL,                              /* tp_print */
	NULL,                              /* tp_getattr */
	NULL,                              /* tp_setattr */
	NULL,                              /* tp_compare */
	certificate_repr,                  /* tp_repr */
	NULL,                              /* tp_as_number */
	NULL,                              /* tp_as_sequence */
	NULL,                              /* tp_as_mapping */
	NULL,                              /* tp_hash */
	NULL,                              /* tp_call */
	certificate_str,                   /* tp_str */
	NULL,                              /* tp_getattro */
	NULL,                              /* tp_setattro */
	NULL,                              /* tp_as_buffer */
	Py_TPFLAGS_BASETYPE|
	Py_TPFLAGS_DEFAULT,                /* tp_flags */
	certificate_doc,                   /* tp_doc */
	NULL,                              /* tp_traverse */
	NULL,                              /* tp_clear */
	NULL,                              /* tp_richcompare */
	0,                                 /* tp_weaklistoffset */
	NULL,                              /* tp_iter */
	NULL,                              /* tp_iternext */
	certificate_methods,               /* tp_methods */
	certificate_members,               /* tp_members */
	certificate_getset,                /* tp_getset */
	NULL,                              /* tp_base */
	NULL,                              /* tp_dict */
	NULL,                              /* tp_descr_get */
	NULL,                              /* tp_descr_set */
	0,                                 /* tp_dictoffset */
	NULL,                              /* tp_init */
	NULL,                              /* tp_alloc */
	certificate_new,                   /* tp_new */
};

static PyObj
context_accept(PyObj self)
{
	Context ctx = (Context) self;
	Transport tls;
	int r;

	tls = create_tls_state(&TransportType, ctx);
	if (tls == NULL)
		return(NULL);

	SSL_set_accept_state(tls->tls_state);

	if (SSL_do_handshake(tls->tls_state) != 0 && library_error("Error", call_handshake))
	{
		Py_DECREF(tls);
		return(NULL);
	}

	return((PyObj) tls);
}

static int
_transport_set_hostname(Transport tls, PyObj hostname)
{
	char *name = NULL;
	Py_ssize_t size = 0;
	int err;

	/* no hostname */
	if (hostname == Py_None)
		return(0);

	if (PyBytes_AsStringAndSize(hostname, &name, &size))
		return(-1);

	err = SSL_set_tlsext_host_name(tls->tls_state, (const char *) name);
	if (err != 1)
	{
		library_error("Error", call_set_hostname);
		return(-1);
	}

	return(0);
}

static PyObj
context_connect(PyObj self, PyObj hostname)
{
	Context ctx = (Context) self;
	Transport tls;
	int r;

	tls = create_tls_state(&TransportType, ctx);
	if (tls == NULL)
		return(NULL);

	if (_transport_set_hostname(tls, hostname))
		goto error;

	SSL_set_connect_state(tls->tls_state);

	if (SSL_do_handshake(tls->tls_state) != 0 && library_error("Error", call_handshake))
		goto error;

	return((PyObj) tls);

	error:
		Py_DECREF((PyObj) tls);
		return(NULL);
}

static PyObj
context_void_sessions(PyObj self, PyObj args)
{
	Context ctx = (Context) self;
	long t = 0;

	if (!PyArg_ParseTuple(args, "l", &t))
		return(NULL);

	SSL_CTX_flush_sessions(ctx->tls_context, t);

	Py_RETURN_NONE;
}

static PyMethodDef
context_methods[] = {
	{"accept", (PyCFunction) context_accept,
		METH_NOARGS, PyDoc_STR(
			"Allocate a server TLS `Transport` instance for "
			"secure transmission of data associated with the Context."
		)
	},

	{"connect", (PyCFunction) context_connect,
		METH_O, PyDoc_STR(
			"Allocate a client TLS `Transport` instance for "
			"secure transmission of data associated with the Context."
		)
	},

	{"void_sessions", (PyCFunction) context_void_sessions,
		METH_VARARGS, PyDoc_STR(
			"Remove the sessions from the context that have expired "
			"according to the given time parameter."
		)
	},

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
context_repr(PyObj self)
{
	Context ctx = (Context) self;
	PyObj rob;

	rob = PyUnicode_FromFormat("<%s %p>", Py_TYPE(ctx)->tp_name, ctx);
	return(rob);
}

static PyObj
context_new(PyTypeObject *subtype, PyObj args, PyObj kw)
{
	static char *kwlist[] = {
		"key",
		"password",
		"certificates",
		"requirements",
		"protocol", /* openssl "method" */
		"ciphers",
		"allow_insecure_ssl_version_two",
		NULL,
	};

	struct password_parameter pwp = {"", 0};

	Context ctx;
	call_t call;

	PyObj key_ob = NULL;
	PyObj certificates = NULL; /* iterable */
	PyObj requirements = NULL; /* iterable */

	char *ciphers = FAULT_OPENSSL_CIPHERS;
	char *protocol = "TLS";

	int allow_ssl_v2 = 0;

	if (!PyArg_ParseTupleAndKeywords(args, kw,
		"|Os#OOssp", kwlist,
		&key_ob,
		&(pwp.words), &(pwp.length),
		&certificates,
		&requirements,
		&protocol,
		&ciphers,
		&allow_ssl_v2
	))
		return(NULL);

	ctx = (Context) subtype->tp_alloc(subtype, 0);
	if (ctx == NULL)
		return(NULL);

	/*
		// The key is checked and loaded later.
	*/
	ctx->tls_key_status = key_none;
	ctx->tls_context = NULL;

	#define X_TLS_METHOD(STRING, PREFIX) \
		else if (strcmp(STRING, protocol) == 0) \
			ctx->tls_context = SSL_CTX_new(PREFIX##_method());

		if (0)
			;
		X_TLS_METHODS()
		else
		{
			PyErr_SetString(PyExc_ValueError, "invalid 'protocol' argument");
			goto fail;
		}
	#undef X_TLS_METHOD

	if (ctx->tls_context == NULL)
	{
		/* XXX: check for openssl failure */
		goto lib_error;
	}
	else
	{
		/*
			// Context initialization.
		*/
		SSL_CTX_set_mode(ctx->tls_context, SSL_MODE_RELEASE_BUFFERS|SSL_MODE_AUTO_RETRY);
		SSL_CTX_set_read_ahead(ctx->tls_context, 1);
	}

	#ifdef SSL_OP_NO_SSLv2
		if (!allow_ssl_v2)
		{
			/*
				// Require exlicit override to allow this.
			*/
			SSL_CTX_set_options(ctx->tls_context, SSL_OP_NO_SSLv2);
		}
	#else
		/* No, SSL_OP_NO_SSLv2 defined by openssl headers */
	#endif

	if (!SSL_CTX_set_cipher_list(ctx->tls_context, ciphers))
		goto lib_error;

	/*
		// Load certificates.
	*/
	if (certificates != NULL)
	{
		if (!load_certificate_chain(ctx->tls_context, certificates))
			goto lib_error;
	}

	if (requirements != NULL)
	{
		if (!load_client_requirements(ctx->tls_context, requirements))
			goto lib_error;
	}

	if (key_ob != NULL)
	{
		pki_key_t key;

		key = load_pem_private_key(key_ob, password_parameter, &pwp);
		if (key == NULL)
		{
			goto lib_error;
		}

		if (SSL_CTX_use_PrivateKey(ctx->tls_context, key)
				&& SSL_CTX_check_private_key(ctx->tls_context))
			ctx->tls_key_status = key_available;
		else
		{
			goto lib_error;
		}
	}

	return((PyObj) ctx);

	lib_error:
	{
		set_openssl_error("Error", 0);
	}
	fail:
	{
		Py_XDECREF(ctx);
		return(NULL);
	}
}

PyDoc_STRVAR(context_doc, "OpenSSL transport security context.");
static PyTypeObject
ContextType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	PYTHON_MODULE_PATH("Context"),   /* tp_name */
	sizeof(struct Context),          /* tp_basicsize */
	0,                               /* tp_itemsize */
	context_dealloc,                 /* tp_dealloc */
	NULL,                            /* tp_print */
	NULL,                            /* tp_getattr */
	NULL,                            /* tp_setattr */
	NULL,                            /* tp_compare */
	context_repr,                    /* tp_repr */
	NULL,                            /* tp_as_number */
	NULL,                            /* tp_as_sequence */
	NULL,                            /* tp_as_mapping */
	NULL,                            /* tp_hash */
	NULL,                            /* tp_call */
	NULL,                            /* tp_str */
	NULL,                            /* tp_getattro */
	NULL,                            /* tp_setattro */
	NULL,                            /* tp_as_buffer */
	Py_TPFLAGS_BASETYPE|
	Py_TPFLAGS_DEFAULT,              /* tp_flags */
	context_doc,                     /* tp_doc */
	NULL,                            /* tp_traverse */
	NULL,                            /* tp_clear */
	NULL,                            /* tp_richcompare */
	0,                               /* tp_weaklistoffset */
	NULL,                            /* tp_iter */
	NULL,                            /* tp_iternext */
	context_methods,                 /* tp_methods */
	context_members,                 /* tp_members */
	NULL,                            /* tp_getset */
	NULL,                            /* tp_base */
	NULL,                            /* tp_dict */
	NULL,                            /* tp_descr_get */
	NULL,                            /* tp_descr_set */
	0,                               /* tp_dictoffset */
	NULL,                            /* tp_init */
	NULL,                            /* tp_alloc */
	context_new,                     /* tp_new */
};

static const char *
termination_string(termination_t i)
{
	switch (i)
	{
		case tls_protocol_error:
			return "error";
		break;

		case tls_remote_termination:
			return "remote";
		break;

		case tls_local_termination:
			return "local";
		break;

		case tls_not_terminated:
			return NULL;
		break;
	}

	return NULL;
}

/**
	// extract the status of the TLS connection
*/
static PyObj
transport_status(PyObj self)
{
	Transport tls = (Transport) self;
	PyObj rob;

	rob = Py_BuildValue("(ssssi)",
		SSL_get_version(tls->tls_state),
		termination_string(tls->tls_termination),
		SSL_state_string(tls->tls_state),
		SSL_state_string_long(tls->tls_state),
		SSL_want(tls->tls_state)
	);

	return(rob);
}

/**
	// SSL_write the buffer entries.
*/
static int
transport_flush(Transport tls)
{
	int xfer, r;
	Py_buffer pb;
	PyObj cwb;

	cwb = output_buffer_initial(tls);
	if (cwb == NULL)
		return(-1);

	if (PyObject_GetBuffer(cwb, &pb, PyBUF_SIMPLE))
	{
		Py_DECREF(cwb);
		output_buffer_pop(tls);
		return(-1);
	}

	if (GetSize(pb))
		xfer = SSL_write(tls->tls_state, GetPointer(pb), GetSize(pb));
	else
		/* zero buffer size, pop it */
		xfer = 1;

	if (xfer < 1)
	{
		if (transport_library_error(tls, call_write))
			r = -2;
		else
		{
			switch (SSL_get_error(tls->tls_state, xfer))
			{
				default:
					r = 0;
				break;
			}
		}
	}
	else
	{
		r = output_buffer_pop(tls);
		if (r >= 0)
		{
			r = 1; /* processed something */
		}
	}

	Py_DECREF(cwb);
	PyBuffer_Release(&pb);

	return(r); /* r < 0 on python error */
}

/**
	// EOF signals.
*/
static PyObj
transport_enciphered_read_eof(PyObj self, PyObj buffer)
{
	Transport tls = (Transport) self;
	BIO_set_mem_eof_return(Transport_GetReadBuffer(tls), 0);
	Py_RETURN_NONE;
}

static PyObj
transport_enciphered_write_eof(PyObj self, PyObj buffer)
{
	Transport tls = (Transport) self;
	BIO_set_mem_eof_return(Transport_GetWriteBuffer(tls), 0);
	Py_RETURN_NONE;
}

#define DEFAULT_READ_SIZE (1024 * 4)

/**
	// Write enciphered protocol data from the remote end into the transport.
	// Either for deciphered reads or for internal protocol management.
	// It is possible that empty buffer sequences return deciphered data.
*/
static PyObj
transport_decipher(PyObj self, PyObj buffer_sequence)
{
	Transport tls = (Transport) self;
	Py_buffer pb;
	int xfer;
	PyObj rob, bufobj;

	/**
		// No need for a queue on decipher as the BIO will function
		// as our buffer. SSL_write will fail during negotiation, but BIO_write won't.
	*/
	PyLoop_ForEach(buffer_sequence, &bufobj)
	{
		Py_ssize_t bsize;

		if (PyObject_GetBuffer(bufobj, &pb, PyBUF_SIMPLE))
			break;

		bsize = GetSize(pb);

		/* BIO_write always appends for memory BIOs */
		xfer = BIO_write(Transport_GetReadBuffer(tls), GetPointer(pb), bsize);
		PyBuffer_Release(&pb);

		if (xfer != bsize && bsize > 0)
		{
			/* http://www.openssl.org/docs/manmaster/crypto/BIO_write.html */
			/* unsupported BIO operation shouldn't happen. */
			assert(xfer != -2);

			/* XXX: improve BIO_write failure */
			PyErr_SetString(PyExc_MemoryError, "ciphertext truncated in buffer");
			break;
		}
	}
	PyLoop_CatchError(buffer_sequence)
	{
		/* XXX: note Transport as broken? */
		return(NULL);
	}
	PyLoop_End()

	rob = PyList_New(0);
	if (rob == NULL)
		return(NULL);

	xfer = 0;
	do
	{
		char *bufptr;
		PyObj buffer;

		buffer = PyByteArray_FromObject(NULL);
		if (buffer == NULL)
		{
			Py_DECREF(rob);
			return(NULL);
		}

		if (PyByteArray_Resize(buffer, DEFAULT_READ_SIZE))
		{
			Py_DECREF(buffer);
			Py_DECREF(rob);
			return(NULL);
		}

		/* Only reference to this bytearray, so don't bother with buffer protocol. */
		bufptr = PyByteArray_AS_STRING(buffer);

		xfer = SSL_read(tls->tls_state, bufptr, DEFAULT_READ_SIZE);
		if (xfer < 1 && transport_library_error(tls, call_read))
		{
			Py_DECREF(buffer);
			break;
		}
		else if (xfer > 0)
		{
			if (PyByteArray_Resize(buffer, MAX(0, xfer)) || PyList_Append(rob, buffer))
			{
				Py_DECREF(buffer);
				Py_DECREF(rob);
				return(NULL);
			}
		}
		else
		{
			/* Check for termination. */
			if (tls->recv_closed_cb != NULL && SSL_get_shutdown(tls->tls_state) & SSL_RECEIVED_SHUTDOWN)
			{
				PyObj cbout;

				cbout = PyObject_CallFunction(tls->recv_closed_cb, NULL);
				Py_DECREF(tls->recv_closed_cb);
				tls->recv_closed_cb = NULL;

				if (cbout)
					Py_DECREF(cbout);
				else
					PyErr_WriteUnraisable(NULL);
			}

		}

		Py_DECREF(buffer); /* New reference owned by return list or error */
	}
	while (xfer == DEFAULT_READ_SIZE);

	/**
		// Check if deciphering caused any writes and drain the transmit side
		// if any callbacks are available.
	*/
	if (BIO_ctrl_pending(Transport_GetWriteBuffer(tls))
		|| SSL_get_error(tls->tls_state, xfer) == SSL_ERROR_WANT_WRITE
		|| output_buffer_has_content(tls) == 1)
	{
		if (tls->send_queued_cb != NULL)
		{
			PyObj cbout;

			cbout = PyObject_CallFunction(tls->send_queued_cb, NULL);

			if (cbout)
				Py_DECREF(cbout);
			else
				PyErr_WriteUnraisable(NULL);
		}
	}

	return(rob);
}

/**
	// Write plaintext data to be enciphered and return the ciphertext to be written
	// to the remote end.
*/
static PyObj
transport_encipher(PyObj self, PyObj buffer_sequence)
{
	Transport tls = (Transport) self;
	int xfer;
	int flush_result;
	char wrote = 0;
	Py_ssize_t queued = 0;
	PyObj rob, r; /* used to check deque operation results */
	BIO *wb = Transport_GetWriteBuffer(tls);

	/* Extend queue unconditionally */
	r = output_buffer_extend(tls, buffer_sequence);
	if (r == NULL)
		return(NULL);

	/* Move buffers out of queue and into the Transport. */
	flushing:
	{
		switch(output_buffer_has_content(tls))
		{
			case 0:
				/* empty output_queue, perform BIO reads */
			break;

			case 1:
				flush_result = transport_flush(tls);
				if (flush_result > 0)
					goto flushing; /* continue */
				else if (flush_result == -2)
				{
					/* protocol error assigned to transport */
					;
				}
				else if (flush_result < 0)
				{
					/* PyErr_Occurred() */
					return(NULL);
				}
				else
				{
					/* empty buffer */
				}
			break;

			default:
				/* output_buffer_has_content error */
				return(NULL);
			break;
		}
	}

	#if !(FV_INJECTIONS())
		/**
			// Avoid early return during tests.
		*/
		if (BIO_ctrl_pending(wb) == 0)
		{
			return(PyTuple_New(0));
		}
	#endif

	rob = PyList_New(0);
	if (rob == NULL)
		return(NULL);

	xfer = 0;
	do
	{
		char *bufptr = 0;
		PyObj buffer;

		buffer = PyByteArray_FromObject(NULL);
		if (buffer == NULL)
			return(NULL);

		if (PyByteArray_Resize(buffer, DEFAULT_READ_SIZE))
		{
			Py_DECREF(buffer);
			Py_DECREF(rob);
			return(NULL);
		}

		/* Only reference to this bytearray, so don't bother with buffer protocol. */
		bufptr = PyByteArray_AS_STRING(buffer);

		xfer = BIO_read(wb, bufptr, DEFAULT_READ_SIZE);
		if (xfer < 0)
		{
			assert(xfer != -2); /* Not Implemented? Memory BIOs implement read */
		}
		else
		{
			if (PyByteArray_Resize(buffer, MAX(0, xfer)) || PyList_Append(rob, buffer))
			{
				/* failed to resize and append */

				Py_DECREF(buffer);
				Py_DECREF(rob);
				return(NULL);
			}
		}

		Py_DECREF(buffer); /* New reference owned by rob; drop our reference. */
	}
	while (xfer == DEFAULT_READ_SIZE);

	return(rob);
}

static PyObj
transport_leak_session(PyObj self)
{
	Transport tls = (Transport) self;

	/*
		// Subsequent terminate() call will not notify the peer.
	*/

	SSL_set_quiet_shutdown(tls->tls_state, 1);
	Py_RETURN_NONE;
}

static PyObj
transport_pending_output(PyObj self)
{
	Transport tls = (Transport) self;
	PyObj rob;

	if (BIO_ctrl_pending(Transport_GetWriteBuffer(tls)))
		rob = Py_True;
	else
	{
		/* must be true if output buffer has data */

		switch (output_buffer_has_content(tls))
		{
			case 1:
				rob = Py_True;
			break;

			case 0:
				rob = Py_False;
			break;

			default:
				return(NULL); /* Python Error */
			break;
		}
	}

	Py_INCREF(rob);
	return(rob);
}

/**
	// Pending reads or data in read buffer (potential read).
*/
static PyObj
transport_pending_input(PyObj self)
{
	Transport tls = (Transport) self;
	PyObj rob;

	if (BIO_ctrl_pending(Transport_GetWriteBuffer(tls)))
		rob = Py_True;
	else if (SSL_pending(tls->tls_state))
		rob = Py_True;
	else
		rob = Py_False;

	Py_INCREF(rob);
	return(rob);
}

/**
	// Should always be zero.
*/
static PyObj
transport_pending(PyObj self)
{
	Transport tls = (Transport) self;
	int nbytes;
	PyObj rob;

	nbytes = SSL_pending(tls->tls_state);
	rob = PyLong_FromLong((long) nbytes);

	return(rob);
}

/**
	// Must be performed for both directions to cause SSL_shutdown().
	// Currently, this method does not sequence termination properly.
*/
static PyObj
transport_terminate(PyObj self, PyObj args)
{
	Transport tls = (Transport) self;
	int direction = 0;

	if (!PyArg_ParseTuple(args, "|i", &direction))
		return(NULL);

	switch (direction)
	{
		case 1:
		case -1:
		case 0:
			/* validity check */
		break;

		default:
			PyErr_SetString(PyExc_ValueError, "invalid termination polarity; must be 1 or -1");
			return(NULL);
		break;
	}

	if (tls->tls_termination != 0)
	{
		/* signals that shutdown seq was already initiated or done */
		Py_INCREF(Py_False);
		return(Py_False);
	}

	/*
		// Both sides must be terminated in order to induce shutdown.
	*/
	if (direction == 0 || tls->tls_terminate + direction == 0)
	{
		SSL_shutdown(tls->tls_state);
		tls->tls_termination = tls_local_termination;
	}
	else
	{
		tls->tls_terminate += direction;
		Py_RETURN_NONE;
	}

	Py_INCREF(Py_True);
	return(Py_True); /* signals that shutdown has been initiated */
}

/**
	// Close writes.
*/
static PyObj
transport_close_output(PyObj self)
{
	Transport tls = (Transport) self;

	if (tls->tls_termination != 0)
	{
		Py_INCREF(Py_False);
		return(Py_False);
	}

	if (SSL_shutdown(tls->tls_state) < 0)
	{
		if (transport_library_error(tls, call_shutdown))
			Py_RETURN_NONE;
	}

	tls->tls_termination = tls_local_termination;

	Py_INCREF(Py_True);
	return(Py_True);
}

static PyObj
transport_connect_transmit_ready(PyObj self, PyObj ob)
{
	Transport tls = (Transport) self;
	Py_XDECREF(tls->send_queued_cb);

	if (ob == Py_None)
		tls->send_queued_cb = NULL;
	else
	{
		tls->send_queued_cb = ob;
		Py_INCREF(ob);
	}

	Py_RETURN_NONE;
}

static PyObj
transport_connect_receive_closed(PyObj self, PyObj ob)
{
	Transport tls = (Transport) self;
	Py_XDECREF(tls->recv_closed_cb);

	if (ob == Py_None)
		tls->recv_closed_cb = NULL;
	else
	{
		tls->recv_closed_cb = ob;
		Py_INCREF(ob);
	}

	Py_RETURN_NONE;
}

static PyMethodDef
transport_methods[] = {
	{"status", (PyCFunction) transport_status,
		METH_NOARGS, PyDoc_STR(
			"Get the transport's status. XXX: ambiguous docs"
		)
	},

	{"leak_session", (PyCFunction) transport_leak_session,
		METH_NOARGS, PyDoc_STR(
			"Force the transport's session to be leaked regardless of its shutdown state.\n"
			"&<http://www.openssl.org/docs/ssl/SSL_set_shutdown.html>"
		)
	},

	{"pending", (PyCFunction) transport_pending,
		METH_NOARGS, PyDoc_STR(
			"Return the number of bytes available for reading."
		)
	},

	{"pending_input", (PyCFunction) transport_pending_input,
		METH_NOARGS, PyDoc_STR(
			"Whether or not the Transport can read data."
		)
	},

	{"pending_output", (PyCFunction) transport_pending_output,
		METH_NOARGS, PyDoc_STR(
			"Whether or not the Transport needs to write data."
		)
	},

	{"terminate", (PyCFunction) transport_terminate,
		METH_VARARGS, PyDoc_STR(
			"Initiate the shutdown sequence for the TLS state. "
			"Enciphered reads and writes must be performed in order to complete the sequence."
		)
	},

	{"close", (PyCFunction) transport_close_output,
		METH_NOARGS, PyDoc_STR("Initiate shutdown closing output.")
	},

	{"encipher", (PyCFunction) transport_encipher,
		METH_O, PyDoc_STR(
			"Encrypt the given plaintext buffers and return the ciphertext buffers."
		)
	},

	{"decipher", (PyCFunction) transport_decipher,
		METH_O, PyDoc_STR(
			"Decrypt the ciphertext buffers into a sequence plaintext buffers."
		)
	},

	{"connect_transmit_ready", (PyCFunction) transport_connect_transmit_ready,
		METH_O, PyDoc_STR("Set callback to be used when an operation causes transmit data.")},

	{"connect_receive_closed", (PyCFunction) transport_connect_receive_closed,
		METH_O, PyDoc_STR("Set callback to be used when peer shutdown has been received.")},

	{NULL},
};

static PyMemberDef
transport_members[] = {
	{"error", T_OBJECT,
		offsetof(struct Transport, tls_protocol_error), READONLY,
		PyDoc_STR(
			"Protocol error data. &None if no *protocol* error occurred."
		)
	},

	{"output_queue", T_OBJECT,
		offsetof(struct Transport, output_queue), READONLY,
		PyDoc_STR("Currently enqueued writes.")
	},

	{NULL},
};

#if OPENSSL_VERSION_NUMBER < 0x1000200fL
	#define SSL_get0_alpn_selected(X, strptr, intptr) { *intptr = 0; }
#endif
/**
	// Get the currently selected application layer protocol.
*/
static PyObj
transport_get_application(PyObj self, void *_)
{
	Transport tls = (Transport) self;
	PyObj rob = NULL;
	const unsigned char *data = NULL;
	unsigned int l = 0;

	SSL_get0_alpn_selected(tls->tls_state, &data, &l);
	if (l > 0)
	{
		rob = PyBytes_FromStringAndSize((const char *) data, l);
	}
	else
	{
		rob = Py_None;
		Py_INCREF(rob);
	}

	return(rob);
}

static PyObj
transport_get_hostname(PyObj self, void *_)
{
	Transport tls = (Transport) self;
	PyObj rob = NULL;
	const char *name = NULL;
	unsigned int l = 0;

	name = SSL_get_servername(tls->tls_state, TLSEXT_NAMETYPE_host_name);
	if (name != NULL)
	{
		rob = PyBytes_FromStringAndSize((const char *) name, strlen(name));
	}
	else
	{
		rob = Py_None;
		Py_INCREF(rob);
	}

	return(rob);
}

/**
	// Get the *TLS* protocol being used by the transport.
*/
static PyObj
transport_get_protocol(PyObj self, void *_)
{
	Transport tls = (Transport) self;
	PyObj rob = NULL;
	const SSL_METHOD *p = SSL_get_ssl_method(tls->tls_state);

	#define X_TLS_PROTOCOL(ORG, STD, SID, NAME, MAJOR_VERSION, MINOR_VERSION, OPENSSL_METHOD) \
		if (p == (OPENSSL_METHOD##_method()) \
			|| p == (OPENSSL_METHOD##_client_method()) \
			|| p == (OPENSSL_METHOD##_server_method)()) \
			rob = Py_BuildValue("sii", #NAME, MAJOR_VERSION, MINOR_VERSION); \
		else
		X_TLS_PROTOCOLS()

		/* final else without an if */
		{
			rob = Py_None;
			Py_INCREF(rob);
		}
	#undef X_TLS_PROTOCOL

	return(rob);
}

static PyObj
transport_get_standard(PyObj self, void *_)
{
	Transport tls = (Transport) self;
	PyObj rob = NULL;
	const SSL_METHOD *p = SSL_get_ssl_method(tls->tls_state);

	#define X_TLS_PROTOCOL(ORG, STD, SID, NAME, MAJOR_VERSION, MINOR_VERSION, OPENSSL_METHOD) \
		if (p == (OPENSSL_METHOD##_method()) \
			|| p == (OPENSSL_METHOD##_client_method()) \
			|| p == (OPENSSL_METHOD##_server_method)()) \
			rob = Py_BuildValue("ssi", #ORG, #STD, SID); \
		else
		X_TLS_PROTOCOLS()

		/* final else without an if */
		{
			rob = Py_None;
			Py_INCREF(rob);
		}
	#undef X_TLS_PROTOCOL

	return(rob);
}

/**
	// SSL_get_peer_cert_chain
*/
static PyObj
transport_get_peer_certificate(PyObj self, void *_)
{
	Transport tls = (Transport) self;

	if (tls->tls_peer_certificate != NULL)
	{
		Py_INCREF(tls->tls_peer_certificate);
		return(tls->tls_peer_certificate);
	}
	else
	{
		Certificate crt;
		certificate_t c;

		c = SSL_get_peer_certificate(tls->tls_state);
		if (c == NULL)
		{
			/* XXX: pop openssl error */
			;
		}
		else
		{
			crt = (Certificate) CertificateType.tp_alloc(&CertificateType, 0);

			if (crt == NULL)
				free_certificate_t(c);
			else
				crt->lib_crt = c;

			return((PyObj) crt);
		}
	}

	Py_RETURN_NONE;
}

static PyObj
transport_get_verror(PyObj self, void *_)
{
	Transport tls = (Transport) self;
	PyObj rob = NULL;
	long vr;

	vr = SSL_get_verify_result(tls->tls_state);
	switch (vr)
	{
		case X509_V_OK:
			Py_INCREF(Py_None);
			return(Py_None);
		break;

		default:
		{
			const char *s;
			s = X509_verify_cert_error_string(vr);
			rob = Py_BuildValue("(ls)", vr, s);
		}
		break;
	}

	Py_INCREF(Py_False);
	return(Py_False);
}

static PyObj
transport_get_terminated(PyObj self, void *_)
{
	Transport tls = (Transport) self;

	if (SSL_get_shutdown(tls->tls_state))
	{
		Py_INCREF(Py_True);
		return(Py_True);
	}

	Py_INCREF(Py_False);
	return(Py_False);
}

static PyGetSetDef transport_getset[] = {
	{"application", transport_get_application, NULL,
		PyDoc_STR("The application protocol specified by the Transport as a bytes instance.\n"),
		NULL,
	},

	{"hostname", transport_get_hostname, NULL,
		PyDoc_STR("Get the hostname used by the Transport"),
		NULL,
	},

	{"protocol", transport_get_protocol, NULL,
		PyDoc_STR("The protocol used by the Transport as a tuple: (name, major, minor).\n"),
		NULL,
	},

	{"standard", transport_get_standard, NULL,
		PyDoc_STR("The protocol standard used by the Transport as a tuple: (org, std, id).\n"),
		NULL,
	},

	{"peer_certificate", transport_get_peer_certificate, NULL,
		PyDoc_STR(
			"Get the peer certificate. If the Transport has yet to receive it, "
			"&None will be returned."
		),
		NULL
	},

	{"verror", transport_get_verror, NULL,
		PyDoc_STR(
			"Verification error. &None if verified, otherise, a pair."
		),
		NULL
	},

	{"terminated", transport_get_terminated, NULL,
		PyDoc_STR("Whether the shutdown state has been *received*."), NULL
	},

	{NULL,},
};

static PyObj
transport_repr(PyObj self)
{
	Transport tls = (Transport) self;
	char *tls_state;
	PyObj rob;

	tls_state = (char *) SSL_state_string(tls->tls_state);

	rob = PyUnicode_FromFormat("<%s [%s] at %p>", Py_TYPE(self)->tp_name, tls_state, self);
	return(rob);
}

static int
transport_clear(PyObj self)
{
	Transport tls = (Transport) self;

	Py_XDECREF(tls->output_queue);
	Py_XDECREF(tls->tls_protocol_error);
	Py_XDECREF(tls->ctx_object);
	Py_XDECREF(tls->recv_closed_cb);
	Py_XDECREF(tls->send_queued_cb);

	(tls->output_queue) = NULL;
	(tls->tls_protocol_error) = NULL;
	(tls->ctx_object) = NULL;
	(tls->recv_closed_cb) = NULL;
	(tls->send_queued_cb) = NULL;

	return(0);
}

static int
transport_traverse(PyObj self, visitproc visit, void *arg)
{
	Transport tls = (Transport) self;

	Py_VISIT(tls->output_queue);
	Py_VISIT(tls->tls_protocol_error);
	Py_VISIT(tls->ctx_object);
	Py_VISIT(tls->recv_closed_cb);
	Py_VISIT(tls->send_queued_cb);

	return(0);
}

static void
transport_dealloc(PyObj self)
{
	Transport tls = (Transport) self;

	if (tls->tls_state == NULL)
		SSL_free(tls->tls_state);

	transport_clear(self);
}

static PyObj
transport_new(PyTypeObject *subtype, PyObj args, PyObj kw)
{
	static char *kwlist[] = {"context", NULL,};
	Context ctx = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "O", kwlist, &ctx))
		return(NULL);

	return((PyObj) create_tls_state(subtype, ctx));
}

PyDoc_STRVAR(transport_doc, "OpenSSL Secure Transfer State.");

static PyTypeObject
TransportType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	PYTHON_MODULE_PATH("Transport"), /* tp_name */
	sizeof(struct Transport),        /* tp_basicsize */
	0,                               /* tp_itemsize */
	transport_dealloc,               /* tp_dealloc */
	NULL,                            /* tp_print */
	NULL,                            /* tp_getattr */
	NULL,                            /* tp_setattr */
	NULL,                            /* tp_compare */
	transport_repr,                  /* tp_repr */
	NULL,                            /* tp_as_number */
	NULL,                            /* tp_as_sequence */
	NULL,                            /* tp_as_mapping */
	NULL,                            /* tp_hash */
	NULL,                            /* tp_call */
	NULL,                            /* tp_str */
	NULL,                            /* tp_getattro */
	NULL,                            /* tp_setattro */
	NULL,                            /* tp_as_buffer */
	Py_TPFLAGS_BASETYPE|
	Py_TPFLAGS_HAVE_GC|
	Py_TPFLAGS_DEFAULT,              /* tp_flags */
	transport_doc,                   /* tp_doc */
	transport_traverse,              /* tp_traverse */
	transport_clear,                 /* tp_clear */
	NULL,                            /* tp_richcompare */
	0,                               /* tp_weaklistoffset */
	NULL,                            /* tp_iter */
	NULL,                            /* tp_iternext */
	transport_methods,               /* tp_methods */
	transport_members,               /* tp_members */
	transport_getset,                /* tp_getset */
	NULL,                            /* tp_base */
	NULL,                            /* tp_dict */
	NULL,                            /* tp_descr_get */
	NULL,                            /* tp_descr_set */
	0,                               /* tp_dictoffset */
	NULL,                            /* tp_init */
	NULL,                            /* tp_alloc */
	transport_new,                   /* tp_new */
};

#define PYTHON_TYPES() \
	ID(Key) \
	ID(Certificate) \
	ID(Context) \
	ID(Transport)

#define MODULE_FUNCTIONS()

#include <fault/python/module.h>
INIT(PyDoc_STR("OpenSSL\n"))
{
	PyObj ob;
	PyObj mod = NULL;

	/*
		// For SSL_write buffer. Needed during negotiations (and handshake).
	*/
	if (Queue == NULL)
	{
		PyObj qmod;
		qmod = PyImport_ImportModule("collections");
		if (qmod == NULL)
			return(NULL);

		Queue = PyObject_GetAttrString(qmod, "deque");
		Py_DECREF(qmod);
		if (Queue == NULL)
			return(NULL);
	}

	/*
		// Initialize OpenSSL.
	*/
	#if OPENSSL_VERSION_NUMBER < 0x10100000L
		SSL_library_init();
	#else
		OPENSSL_init_ssl(0, NULL);
	#endif

	SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	OpenSSL_add_ssl_algorithms();

	CREATE_MODULE(&mod);
	if (mod == NULL)
		return(NULL);

	if (PyModule_AddIntConstant(mod, "version_code", OPENSSL_VERSION_NUMBER))
		goto error;

	if (PyModule_AddStringConstant(mod, "version", OPENSSL_VERSION_TEXT))
		goto error;

	if (PyModule_AddStringConstant(mod, "ciphers", FAULT_OPENSSL_CIPHERS))
		goto error;

	/*
		// Break up the version into sys.version_info style tuple.
		// 0x1000105fL is 1.0.1e final
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
		// Initialize types.
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
	{
		DROP_MODULE(mod);
		return(NULL);
	}
}
