#if 0
csource = """
#endif
/*
 * shade/openssl.py.c - openssl access
 *
 * SSL_CTX_set_client_cert_cb()
 * SSL_ERROR_WANT_X509_LOOKUP (SSL_get_error return)
 * * The OpenSSL folks note a significant limitation of this feature as
 * * that the callback functions cannot return a full chain. However,
 * * if the chain is pre-configured on the Context, the full chain will be sent.
 * * The current implementation of OpenSSL means that a callback selecting
 * * the exact chain is... limited.
 */
/*
 *
 * X509_NAMES = SSL_get_client_CA_list(transport_t) - client connection get server (requirements) CA list.
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

#include <openssl/objects.h>

#ifdef OPENSSL_NO_EVP
#error requires openssl with EVP
#endif

#if 0
#ifndef OSSL_NIDS
/*
 * OSSL_NIDS() is defined by the probe and pre-included.
 */
#error probe module did not render OSSL_NIDS template macro
#endif
#endif

#ifndef SHADE_OPENSSL_CIPHERS
#define SHADE_OPENSSL_CIPHERS "RC4:HIGH:!aNULL:!eNULL:!NULL:!MD5"
#endif

/*
 * Security Context [Cipher/Protocol Parameters]
 */
typedef SSL_CTX *context_t;
#define free_context_t SSL_CTX_free

/*
 * An instance of TLS. [Connection] State
 */
typedef SSL *transport_t;
#define free_transport_t SSL_free

/*
 * A Certificate.
 */
typedef X509 *certificate_t;
#define free_certificate_t X509_free

/*
 * Public or Private Key
 */
typedef EVP_PKEY *pki_key_t;

/*
 * TLS parameter for keeping state with memory instead of sockets.
 */
typedef struct {
	BIO *ossl_breads;
	BIO *ossl_bwrites;
} memory_t;

typedef enum {
	tls_protocol_error = -3,		/* effectively terminated */
	tls_remote_termination = -2,	/* shutdown from remote */
	tls_local_termination = -1,	/* shutdown from local request */
	tls_not_terminated = 0,
	tls_terminating = 1,
} termination_t;

typedef enum {
	key_none,
	key_required,
	key_available
} key_status_t;

static PyObj version_info = NULL, version_str = NULL;

struct Certificate {
	PyObject_HEAD
	certificate_t ossl_crt;
};
typedef struct Certificate *Certificate;

struct Context {
	PyObject_HEAD
	context_t tls_context;
	key_status_t tls_key_status;
};
typedef struct Context *Context;

struct Transport {
	PyObject_HEAD
	Context ctx_object;

	transport_t tls_state;
	memory_t tls_memory;

	termination_t tls_termination;
	PyObj tls_protocol_error; /* dictionary or NULL (None) */

	/*
	 * NULL until inspected then cached until the Transport is terminated.
	 */
	PyObj tls_peer_certificate;

	/*
	 * These are updated when I/O of any sort occurs and
	 * provides a source for event signalling.
	 */
	unsigned long tls_pending_reads, tls_pending_writes;
};
typedef struct Transport *Transport;

static PyTypeObject ContextType, TransportType;

#define GetPointer(pb) (pb.buf)
#define GetSize(pb) (pb.len)

/*
 * OpenSSL doesn't provide us with an X-Macro of any sort, so hand add as needed.
 * Might have to probe... =\
 *
 * ORG, TYPE, ID, NAME, VERSION, OSSL_FRAGMENT
 */
#define X_TLS_PROTOCOLS() \
	X_TLS_PROTOCOL(ietf.org, RFC, 6101, SSL, 3, 0, SSLv23)	\
	X_TLS_PROTOCOL(ietf.org, RFC, 2246, TLS, 1, 0, TLSv1)		\
	X_TLS_PROTOCOL(ietf.org, RFC, 4346, TLS, 1, 1, TLSv1_1)	\
	X_TLS_PROTOCOL(ietf.org, RFC, 5246, TLS, 1, 2, TLSv1_2)

#define X_CERTIFICATE_TYPES() \
	X_CERTIFICATE_TYPE(ietf.org, RFC, 5280, X509)

/*
 * TODO
 * Context Cipher List Specification
 * Context Certificate Loading
 * Context Certificate Loading
 */
#define X_TLS_ALGORITHMS()	\
	X_TLS_ALGORITHMS(RSA)	\
	X_TLS_ALGORITHMS(DSA)	\
	X_TLS_ALGORITHMS(DH)

#define X_CA_EVENTS()			\
	X_CA_EVENT(CSR, REQUEST)	\
	X_CA_EVENT(CRL, REVOKE)

/*
 * Function Set to load Security Elements.
 */
#define X_READ_OSSL_OBJECT(TYP, LOCAL_SYM, OSSL_CALL) \
static TYP \
LOCAL_SYM(PyObj buf, pem_password_cb *cb, void *cb_data) \
{ \
	Py_buffer pb; \
	TYP element = NULL; \
	BIO *bio; \
\
	if (PyObject_GetBuffer(buf, &pb, 0)) \
		return(NULL); XCOVERAGE \
\
	/* Implicit Read-Only BIO: Py_buffer data is directly referenced. */ \
	bio = BIO_new_mem_buf(GetPointer(pb), GetSize(pb)); \
	if (bio == NULL) \
	{ \
		PyErr_SetString(PyExc_MemoryError, "could not allocate OpenSSL memory for security object"); \
	} \
	else \
	{ \
		element = OSSL_CALL(bio, NULL, cb, cb_data); \
		BIO_free(bio); \
	} \
\
	PyBuffer_Release(&pb); \
	return(element); \
}

/*
 * need a small abstraction
 */
X_READ_OSSL_OBJECT(certificate_t, load_pem_certificate, PEM_read_bio_X509)
X_READ_OSSL_OBJECT(pki_key_t, load_pem_private_key, PEM_read_bio_PrivateKey)
X_READ_OSSL_OBJECT(pki_key_t, load_pem_public_key, PEM_read_bio_PUBKEY)
#undef X_READ_OSSL_OBJECT

/*
 * OpenSSL uses a per-thread error queue, but
 * there is storage space on our objects for this very case.
 */
static PyObj
pop_openssl_error(void)
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
		"((sk)(ss)(ss)(ss)(ss)(ss)(si))",
			"code", error_code,
			"library", lib,
			"function", func,
			"reason", reason,
			"data", data,
			"path", path,
			"line", line
	);

	if (flags & ERR_TXT_MALLOCED && data != NULL)
		free((void *) data);

	return(rob);
}

static void
set_openssl_error(const char *exc_name)
{
	PyObj err, exc = import_sibling("core", exc_name);
	if (exc == NULL)
		return;

	err = pop_openssl_error();
	PyErr_SetObject(exc, err);
}

/*
 * primary transport_new parts. Normally called by the Context methods.
 */
static Transport
create_tls_state(PyTypeObject *typ, Context ctx)
{
	const static char *mem_err_str = "could not allocate memory BIO for secure Transport";
	Transport tls;

	tls = (Transport) typ->tp_alloc(typ, 0);
	if (tls == NULL)
		return(NULL); XCOVERAGE

	tls->ctx_object = ctx;

	tls->tls_state = SSL_new(ctx->tls_context);
	if (tls->tls_state == NULL)
	{
		set_openssl_error("AllocationError");
		Py_DECREF(tls);
		return(tls);
	}

	Py_INCREF(((PyObj) ctx));

	/*
	 * I/O buffers for the connection.
	 *
	 * Unlike SSL_new error handling, be noisy about memory errors.
	 */
	tls->tls_memory.ossl_breads = BIO_new(BIO_s_mem());
	if (tls->tls_memory.ossl_breads == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, mem_err_str);
		goto fail;
	}

	tls->tls_memory.ossl_bwrites = BIO_new(BIO_s_mem());
	if (tls->tls_memory.ossl_bwrites == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, mem_err_str);
		goto fail;
	}

	SSL_set_bio(tls->tls_state, tls->tls_memory.ossl_breads, tls->tls_memory.ossl_bwrites);

	return(tls);
fail:
	Py_DECREF(tls);
	return(NULL);
}

static int
update_io_sizes(Transport tls)
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
 * Update the error status of the Transport object.
 * Flip state bits if necessary.
 */
static void
check_result(Transport tls, int result)
{
	switch(result)
	{
		/*
		 * Expose the needs of the TLS state?
		 * XXX: pending size checks may cover this.
		 */
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
		break;

		case SSL_ERROR_NONE:
		break;

		case SSL_ERROR_ZERO_RETURN:
			/*
			 * Terminated.
			 */
			switch (tls->tls_termination)
			{
				case tls_terminating:
					tls->tls_termination = tls_local_termination;
				break;

				case tls_not_terminated:
					tls->tls_termination = tls_remote_termination;
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
			tls->tls_protocol_error = pop_openssl_error();
			tls->tls_termination = tls_protocol_error;
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
 * Loading certificates from an iterator is common, so
 * a utility macro. Would be a function, but some load ops are macros.
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
		cert = load_pem_certificate(ob, NULL, NULL); /* XXX: select type */ \
		Py_DECREF(ob); \
\
		if (cert == NULL) \
		{ \
			if (PyErr_Occurred()) \
				goto py_fail; \
			else \
				goto ossl_fail; \
		} \
\
		if (!INITIAL(ctx, cert)) \
			goto ossl_fail; \
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
				goto ossl_fail; \
			if (!SUBSEQUENT(ctx, cert)) \
				goto ossl_fail; \
		} \
	} \
\
	Py_DECREF(pi); \
	return(1); \
\
ossl_fail: \
	PyErr_SetString(PyExc_RuntimeError, "ossl fail"); \
py_fail: \
	Py_DECREF(pi); \
	return(0); \
}

CERT_INIT_LOOP(load_certificate_chain, SSL_CTX_use_certificate, SSL_CTX_add_extra_chain_cert)
CERT_INIT_LOOP(load_client_requirements, SSL_CTX_add_client_CA, SSL_CTX_add_client_CA)

/* void SSL_CTX_flush_sessions(SSL_CTX *s, long t); */

/*
 * certificate_rallocate() - create a new Transport object using the security context
 */
static PyObj
certificate_open(PyObj subtype)
{
	Certificate crt;

	Py_RETURN_NONE;
}

static PyMethodDef
certificate_methods[] = {
	{"open", (PyCFunction) certificate_open,
		METH_CLASS|METH_NOARGS, PyDoc_STR(
"open()\n\n"
"Read a certificate directly from the filesystem."
"\n"
)},

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
/*
	X509_get_serialNumber
	X509_get_signature_type
*/

static PyObj
key_from_ossl_key(EVP_PKEY *k)
{
	Py_RETURN_NONE;
}

static PyObj
str_from_asn1_string(ASN1_STRING *str)
{
	PyObj rob;
	char *utf = NULL;
	int len = 0;

	len = ASN1_STRING_to_UTF8(&utf, str);
	rob = PyUnicode_FromStringAndSize(utf, len);

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

		item = X509_NAME_get_entry(n, i);
		iob = X509_NAME_ENTRY_get_object(item);

		val = str_from_asn1_string(X509_NAME_ENTRY_get_data(item));
		if (val == NULL)
		{
			Py_DECREF(rob);
			return(NULL);
		}

		nid = OBJ_obj2nid(iob);

		robi = Py_BuildValue("(iO)", nid, val);

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
	 * The other variants are strings as well...
	 * The UTCTIME strings omit the century and millennium parts of the year.
	 */
	gt = ASN1_TIME_to_generalizedtime(t, NULL);
	rob = PyUnicode_FromStringAndSize(M_ASN1_STRING_data(gt), M_ASN1_STRING_length(gt));
	M_ASN1_GENERALIZEDTIME_free(gt);

	return(rob);
}

#define CERTIFICATE_PROPERTIES() \
	CERT_PROPERTY(not_before_string, "The 'notBefore' field as a UNIX timestamp", X509_get_notBefore, str_from_asn1_time) \
	CERT_PROPERTY(not_after_string, "The 'notAfter' field as a UNIX timestamp", X509_get_notAfter, str_from_asn1_time) \
	CERT_PROPERTY(signature_type, "The type of used to sign the key.", X509_extract_key, key_from_ossl_key) \
	CERT_PROPERTY(subject, "The raw subject data of the cerficate.", X509_get_subject_name, seq_from_names) \
	CERT_PROPERTY(public_key, "The public key provided by the certificate.", X509_extract_key, key_from_ossl_key) \
	CERT_PROPERTY(version, "The Format Version", X509_get_version, PyLong_FromLong)

#define CERT_PROPERTY(NAME, DOC, GET, CONVERT) \
static PyObj certificate_get_##NAME(PyObj crt) \
{ \
	certificate_t ossl_crt = ((Certificate) crt)->ossl_crt; \
	return(CONVERT(GET(ossl_crt))); \
} \

CERTIFICATE_PROPERTIES()
#undef CERT_PROPERTY

static PyGetSetDef certificate_getset[] = {
#define CERT_PROPERTY(NAME, DOC, UNUSED1, UNUSED2) {#NAME, certificate_get_##NAME, NULL, PyDoc_STR(DOC)},

CERTIFICATE_PROPERTIES()
#undef CERT_PROPERTY
	{NULL,},
};

static void
certificate_dealloc(PyObj self)
{
	Certificate cert = (Certificate) self;
	X509_free(cert->ossl_crt);
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

	sn = X509_get_subject_name(cert->ossl_crt);

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
	X509_print(b, cert->ossl_crt);

	size = BIO_get_mem_data(b, &ptr);

	rob = Py_BuildValue("s#", ptr, size);

	BIO_free(b);

	return(rob);
}

static PyObj
certificate_new(PyTypeObject *subtype, PyObj args, PyObj kw)
{
	static char *kwlist[] = {"pem", NULL,};
	PyObj pem;
	Certificate cert;

	if (!PyArg_ParseTupleAndKeywords(args, kw,
		"O", kwlist, &pem
	))
		return(NULL); XCOVERAGE

	cert = (Certificate) subtype->tp_alloc(subtype, 0);
	if (cert == NULL)
	{
		return(NULL); XCOVERAGE
	}

	cert->ossl_crt = load_pem_certificate(pem, NULL, NULL);
	if (cert->ossl_crt == NULL)
		goto ossl_error;

	return((PyObj) cert);
ossl_error:
	set_openssl_error("Error");
fail:
	Py_XDECREF(cert);
	return(NULL);
}

PyDoc_STRVAR(certificate_doc,
"OpenSSL X509 Certificate Objects");

static PyTypeObject
CertificateType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	QPATH("Certificate"),		/* tp_name */
	sizeof(struct Certificate),/* tp_basicsize */
	0,									/* tp_itemsize */
	certificate_dealloc,			/* tp_dealloc */
	NULL,								/* tp_print */
	NULL,								/* tp_getattr */
	NULL,								/* tp_setattr */
	NULL,								/* tp_compare */
	certificate_repr,				/* tp_repr */
	NULL,								/* tp_as_number */
	NULL,								/* tp_as_sequence */
	NULL,								/* tp_as_mapping */
	NULL,								/* tp_hash */
	NULL,								/* tp_call */
	certificate_str,				/* tp_str */
	NULL,								/* tp_getattro */
	NULL,								/* tp_setattro */
	NULL,								/* tp_as_buffer */
	Py_TPFLAGS_BASETYPE|
	Py_TPFLAGS_DEFAULT,			/* tp_flags */
	certificate_doc,				/* tp_doc */
	NULL,								/* tp_traverse */
	NULL,								/* tp_clear */
	NULL,								/* tp_richcompare */
	0,									/* tp_weaklistoffset */
	NULL,								/* tp_iter */
	NULL,								/* tp_iternext */
	certificate_methods,			/* tp_methods */
	certificate_members,			/* tp_members */
	certificate_getset,			/* tp_getset */
	NULL,								/* tp_base */
	NULL,								/* tp_dict */
	NULL,								/* tp_descr_get */
	NULL,								/* tp_descr_set */
	0,									/* tp_dictoffset */
	NULL,								/* tp_init */
	NULL,								/* tp_alloc */
	certificate_new,				/* tp_new */
};

/*
 * context_rallocate() - create a new Transport object using the security context
 */
static PyObj
context_rallocate(PyObj self)
{
	Context ctx = (Context) self;
	Transport tls;

	tls = create_tls_state(&TransportType, ctx);
	if (tls == NULL)
		return(NULL);

	/*
	 * Presence of key indicates server.
	 */
	if (ctx->tls_key_status == key_available)
		SSL_set_accept_state(tls->tls_state);
	else
		SSL_set_connect_state(tls->tls_state);

	/*
	 * Initialize with a do_handshake.
	 */
	check_result(tls, SSL_get_error(tls->tls_state, SSL_do_handshake(tls->tls_state)));

	return((PyObj) tls);
}

static PyMethodDef
context_methods[] = {
	{"rallocate", (PyCFunction) context_rallocate,
		METH_NOARGS, PyDoc_STR(
"rallocate()\n\n"
"Allocate a TLS :py:class:`Transport` instance for secure transmission of data associated with the Context."
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
		"certificates",
		"requirements",
		"protocol", /* openssl "method" */
		"ciphers",
		"allow_insecure_ssl_version_two",
		NULL,
	};

	Context ctx;

	PyObj key_ob = NULL;
	PyObj certificates = NULL; /* iterable */
	PyObj requirements = NULL; /* iterable */

	char *ciphers = SHADE_OPENSSL_CIPHERS;
	char *protocol = "compat";

	int allow_ssl_v2 = 0;

	if (!PyArg_ParseTupleAndKeywords(args, kw,
		"|OOOssp", kwlist,
		&key_ob,
		&certificates,
		&requirements,
		&protocol,
		&ciphers,
		&allow_ssl_v2
	))
		return(NULL); XCOVERAGE

	ctx = (Context) subtype->tp_alloc(subtype, 0);
	if (ctx == NULL)
		return(NULL); XCOVERAGE

	/*
	 * The key is checked and loaded later.
	 */
	ctx->tls_key_status = key_none;

	if (strcmp(protocol, "TLS-1.2") == 0)
	{
		ctx->tls_context = SSL_CTX_new(TLSv1_2_method());
	}
	else if (strcmp(protocol, "TLS-1.1") == 0)
	{
		ctx->tls_context = SSL_CTX_new(TLSv1_1_method());
	}
	else if (strcmp(protocol, "TLS-1.0") == 0)
	{
		ctx->tls_context = SSL_CTX_new(TLSv1_method());
	}
	else if (strcmp(protocol, "SSL-3.0") == 0)
	{
		ctx->tls_context = SSL_CTX_new(SSLv3_method());
	}
	else if (strcmp(protocol, "compat") == 0)
	{
		ctx->tls_context = SSL_CTX_new(SSLv23_method());
	}
	else
	{
		PyErr_SetString(PyExc_TypeError, "invalid 'protocol' argument");
		goto fail;
	}

#ifdef SSL_OP_NO_SSLv2
	if (!allow_ssl_v2)
	{
		/*
		 * Require exlicit override to allow this.
		 */
		SSL_CTX_set_options(ctx->tls_context, SSL_OP_NO_SSLv2);
	}
#else
#endif

	if (!SSL_CTX_set_cipher_list(ctx->tls_context, ciphers))
		goto ossl_error;

	/*
	 * Load certificates.
	 */
	if (certificates != NULL)
	{
		if (!load_certificate_chain(ctx->tls_context, certificates))
			goto ossl_error;
	}

	if (requirements != NULL)
	{
		if (!load_client_requirements(ctx->tls_context, requirements))
			goto ossl_error;
	}

	if (key_ob != NULL)
	{
		pki_key_t key;

		key = load_pem_private_key(key_ob, NULL, NULL);
		if (key == NULL)
		{
			goto ossl_error;
		}

		if (SSL_CTX_use_PrivateKey(ctx->tls_context, key) && SSL_CTX_check_private_key(ctx->tls_context))
			ctx->tls_key_status = key_available;
		else
		{
			goto ossl_error;
		}
	}

	return((PyObj) ctx);
ossl_error:
	set_openssl_error("ContextError");
fail:
	Py_XDECREF(ctx);
	return(NULL);
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

		case tls_terminating:
			return "terminating";
		break;

		case tls_not_terminated:
			return NULL;
		break;
	}
}

/*
 * transport_status() - extract the status of the TLS connection
 */
static PyObj
transport_status(PyObj self)
{
	Transport tls = (Transport) self;
	PyObj rob;

	rob = Py_BuildValue("(siss)",
		termination_string(tls->tls_termination),
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
transport_read_enciphered(PyObj self, PyObj buffer)
{
	Transport tls = (Transport) self;
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
		/*
		 * Check .error =\
		 */
		xfer = 0;
	}
	update_io_sizes(tls);

	return(PyLong_FromLong((long) xfer));
}

/*
 * EOF signals.
 */
static PyObj
transport_enciphered_read_eof(PyObj self, PyObj buffer)
{
	Transport tls = (Transport) self;
	BIO_set_mem_eof_return(tls->tls_memory.ossl_breads, 0);
	Py_RETURN_NONE;
}

static PyObj
transport_enciphered_write_eof(PyObj self, PyObj buffer)
{
	Transport tls = (Transport) self;
	BIO_set_mem_eof_return(tls->tls_memory.ossl_bwrites, 0);
	Py_RETURN_NONE;
}

/*
 *
 */
static PyObj
transport_write_enciphered(PyObj self, PyObj buffer)
{
	char peek[sizeof(int)];
	Transport tls = (Transport) self;
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
		xfer = 0;
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
transport_read_deciphered(PyObj self, PyObj buffer)
{
	Transport tls = (Transport) self;
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
transport_write_deciphered(PyObj self, PyObj buffer)
{
	Transport tls = (Transport) self;
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
transport_leak_session(PyObj self)
{
	Transport tls = (Transport) self;

	/*
	 * Subsequent terminate() call will not notify the peer.
	 */
	SSL_set_quiet_shutdown(tls->tls_state, 1);
	Py_RETURN_NONE;
}

static PyObj
transport_terminate(PyObj self)
{
	Transport tls = (Transport) self;

	if (tls->tls_termination != 0)
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
transport_methods[] = {
	{"status", (PyCFunction) transport_status,
		METH_NOARGS, PyDoc_STR(
"status()\n\n"
"\n"
)},
	{"leak_session", (PyCFunction) transport_leak_session,
		METH_NOARGS, PyDoc_STR(
"leak_session()\n\n"
"Force the transport's session to be leaked regardless of its shutdown state.\n"
"`<http://www.openssl.org/docs/ssl/SSL_set_shutdown.html>`_"
"\n"
)},

	{"terminate", (PyCFunction) transport_terminate,
		METH_NOARGS, PyDoc_STR(
"terminate()\n\n"
"Initiate the shutdown sequence for the TLS state."
"Enciphered reads and writes must be performed in order to complete the sequence."
"\n"
)},

	{"read_enciphered", (PyCFunction) transport_read_enciphered,
		METH_O, PyDoc_STR(
"read_enciphered(buffer)\n\n"
"Get enciphered data to be written to the remote endpoint. Transfer to be written."
"\n"
)},
	{"write_enciphered", (PyCFunction) transport_write_enciphered,
		METH_O, PyDoc_STR(
"write_enciphered()\n\n"
"Put enciphered data into the TLS channel to be later decrypted and retrieved with read_deciphered."
"\n"
)},

	{"read_deciphered", (PyCFunction) transport_read_deciphered,
		METH_O, PyDoc_STR(
"read_deciphered()\n\n"
"Get decrypted data from the TLS channel for processing by the local endpoint."
"\n"
)},
	{"write_deciphered", (PyCFunction) transport_write_deciphered,
		METH_O, PyDoc_STR(
"write_deciphered(buffer)\n\n"
"Put decrypted data into the TLS channel to be sent to the remote endpoint after encryption."
"\n"
)},

	{NULL,},
};

static PyMemberDef
transport_members[] = {
	{"error", T_OBJECT, offsetof(struct Transport, tls_protocol_error), READONLY,
		PyDoc_STR("Protocol error data. :py:obj:`None` if no *protocol* error occurred.")},
	{"pending_enciphered_writes", T_ULONG, offsetof(struct Transport, tls_pending_writes), READONLY,
		PyDoc_STR("Snapshot of the Transport's out-going buffer used for writing. Growth indicates need for lower-level write.")},
	{"pending_enciphered_reads", T_ULONG, offsetof(struct Transport, tls_pending_reads), READONLY,
		PyDoc_STR("Snapshot of the Transport's incoming buffer used for reading. Growth indicates need for higher-level read attempt.")},
	{NULL,},
};

static PyObj
transport_get_protocol(PyObj self, void *_)
{
	Transport tls = (Transport) self;
	PyObj rob = NULL;
	intptr_t p = (intptr_t) SSL_get_ssl_method(tls->tls_state);

	/*
	 * XXX: not working... =\
	 */
#define X_TLS_PROTOCOL(ORG, STD, SID, NAME, MAJOR_VERSION, MINOR_VERSION, OSSL_METHOD) \
	if (p == ((intptr_t) OSSL_METHOD##_method) \
		|| p ==((intptr_t) OSSL_METHOD##_client_method) \
		|| p == ((intptr_t) OSSL_METHOD##_server_method)) \
		rob = Py_BuildValue("(ssi)sii", #ORG, #STD, SID, #NAME, MAJOR_VERSION, MINOR_VERSION); \
	else
	X_TLS_PROTOCOLS()
	{
		rob = Py_None;
		Py_INCREF(rob);
	}
#undef X_TLS_PROTOCOL

	return(rob);
}

/* SSL_get_peer_cert_chain */
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
		if (c != NULL)
		{
			crt = (Certificate) CertificateType.tp_alloc(&CertificateType, 0);
			if (crt == NULL)
				return(NULL); XCOVERAGE

			if (crt == NULL)
				free_certificate_t(c);
			else
				crt->ossl_crt = c;
			return(crt);
		}
	}

	Py_RETURN_NONE;
}

static PyGetSetDef transport_getset[] = {
	{"protocol", transport_get_protocol, NULL,
		PyDoc_STR(
"The protocol used by the Transport.\n"
)},
	{"peer_certificate", transport_get_peer_certificate, NULL,
		PyDoc_STR(
"peer_certificate\n\n"
"Get the peer certificate. If the Transport has yet to receive it, :py:obj:`None` will be returned."
"\n"
)},
	{NULL,},
};

static PyObj
transport_repr(PyObj self)
{
	Transport tls = (Transport) self;
	char *tls_state;
	PyObj rob;

	tls_state = SSL_state_string(tls->tls_state);

	rob = PyUnicode_FromFormat("<%s %p[%s]>", Py_TYPE(self)->tp_name, self, tls_state);

	return(rob);
}

static void
transport_dealloc(PyObj self)
{
	Transport tls = (Transport) self;
	memory_t *mp = &(tls->tls_memory);

	if (tls->tls_state == NULL)
		SSL_free(tls->tls_state);

	if (mp->ossl_breads != NULL)
		BIO_free(mp->ossl_breads);
	if (mp->ossl_bwrites != NULL)
		BIO_free(mp->ossl_bwrites);

	Py_XDECREF(tls->tls_protocol_error);
	Py_XDECREF(tls->ctx_object);
}

static PyObj
transport_new(PyTypeObject *subtype, PyObj args, PyObj kw)
{
	static char *kwlist[] = {"context", NULL,};
	Context ctx = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "O", kwlist, &ctx))
		return(NULL); XCOVERAGE

	return((PyObj) create_tls_state(subtype, ctx));
}

PyDoc_STRVAR(transport_doc,
"OpenSSL Secure Transfer State.");

static PyTypeObject
TransportType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	QPATH("Transport"),			/* tp_name */
	sizeof(struct Transport),	/* tp_basicsize */
	0,									/* tp_itemsize */
	transport_dealloc,			/* tp_dealloc */
	NULL,								/* tp_print */
	NULL,								/* tp_getattr */
	NULL,								/* tp_setattr */
	NULL,								/* tp_compare */
	transport_repr,				/* tp_repr */
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
	transport_doc,					/* tp_doc */
	NULL,								/* tp_traverse */
	NULL,								/* tp_clear */
	NULL,								/* tp_richcompare */
	0,									/* tp_weaklistoffset */
	NULL,								/* tp_iter */
	NULL,								/* tp_iternext */
	transport_methods,			/* tp_methods */
	transport_members,			/* tp_members */
	transport_getset,				/* tp_getset */
	NULL,								/* tp_base */
	NULL,								/* tp_dict */
	NULL,								/* tp_descr_get */
	NULL,								/* tp_descr_set */
	0,									/* tp_dictoffset */
	NULL,								/* tp_init */
	NULL,								/* tp_alloc */
	transport_new,					/* tp_new */
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
	ID(Certificate) \
	ID(Context) \
	ID(Transport)

INIT(PyDoc_STR("OpenSSL\n"))
{
	PyObj ob;
	PyObj mod = NULL;

	/*
	 * Initialize OpenSSL.
	 */
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_ssl_algorithms();

	CREATE_MODULE(&mod);
	if (mod == NULL)
		return(NULL); XCOVERAGE

	if (PyModule_AddIntConstant(mod, "version_code", OPENSSL_VERSION_NUMBER))
		goto error;

	if (PyModule_AddStringConstant(mod, "version", OPENSSL_VERSION_TEXT))
		goto error;

	if (PyModule_AddStringConstant(mod, "ciphers", SHADE_OPENSSL_CIPHERS))
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
