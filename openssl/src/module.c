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
#include <openssl/rsa.h>
#include <openssl/evp.h>

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
	tls_protocol_error = -3,     /* effectively terminated */
	tls_remote_termination = -2, /* shutdown from remote */
	tls_local_termination = -1,  /* shutdown from local request */
	tls_not_terminated = 0,
	tls_terminating = 1,
} termination_t;

typedef enum {
	key_none,
	key_required,
	key_available
} key_status_t;

static PyObj version_info = NULL, version_str = NULL;

struct Key {
	PyObject_HEAD
	pki_key_t lib_key;
};
typedef struct Key *Key;

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

static PyTypeObject KeyType, CertificateType, ContextType, TransportType;

#define GetPointer(pb) (pb.buf)
#define GetSize(pb) (pb.len)

/*
 * Prompting is rather inappropriate from a library;
 * this callback is used throughout the source to manage
 * the encryption key of a certificate or private key.
 */
struct password_parameter {
	char *words;
	Py_ssize_t length;
};

/*
 * Callback used to parameterize the password.
 */
static int
password_parameter(char *buf, int size, int rwflag, void *u)
{
	struct password_parameter *pwp = u;

	strncpy(buf, pwp->words, (size_t) size);
	return((int) pwp->length);
}

/*
 * OpenSSL doesn't provide us with an X-Macro of any sort, so hand add as needed.
 * Might have to rely on some probes at some point... =\
 *
 * ORG, TYPE, ID, NAME, VERSION, OSSL_FRAGMENT
 */
#define X_TLS_PROTOCOLS() \
	X_TLS_PROTOCOL(ietf.org, RFC, 2246, TLS,  1, 0, TLSv1)    \
	X_TLS_PROTOCOL(ietf.org, RFC, 4346, TLS,  1, 1, TLSv1_1)  \
	X_TLS_PROTOCOL(ietf.org, RFC, 5246, TLS,  1, 2, TLSv1_2)  \
	X_TLS_PROTOCOL(ietf.org, RFC, 6101, SSL,  3, 0, SSLv23)   \
	X_TLS_PROTOCOL(ietf.org, RFC, 4347, DTLS, 1, 0, DTLSv1)   \
	X_TLS_PROTOCOL(ietf.org, RFC, 6347, DTLS, 1, 2, DTLSv1_2)

#define X_CERTIFICATE_TYPES() \
	X_CERTIFICATE_TYPE(ietf.org, RFC, 5280, X509)

/*
 * TODO
 * Context Cipher List Specification
 * Context Certificate Loading
 * Context Certificate Loading
 */
#define X_TLS_ALGORITHMS() \
	X_TLS_ALGORITHMS(RSA)  \
	X_TLS_ALGORITHMS(DSA)  \
	X_TLS_ALGORITHMS(DH)

#define X_CA_EVENTS()        \
	X_CA_EVENT(CSR, REQUEST) \
	X_CA_EVENT(CRL, REVOKE)

#define X_TLS_METHODS()               \
	X_TLS_METHOD("TLS", TLS)          \
	X_TLS_METHOD("TLS-1.0", TLSv1)    \
	X_TLS_METHOD("TLS-1.1", TLSv1_1)  \
	X_TLS_METHOD("TLS-1.2", TLSv1_2)  \
	X_TLS_METHOD("SSL-3.0", SSLv3)    \
	X_TLS_METHOD("compat",  SSLv23)

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

	return(k);

	lib_error:
	{
		if (ctx != NULL)
			EVP_PKEY_CTX_free(ctx);

		set_openssl_error("Error");
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
	switch (EVP_PKEY_type(k->lib_key->type))
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
}

static PyObj
key_get_type(PyObj self)
{
	Key k = (Key) self;

	return(PyUnicode_FromString(key_type_string(k)));
}

static PyMethodDef
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
		set_openssl_error("Error");

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
		return(NULL); XCOVERAGE

	k = (Key) subtype->tp_alloc(subtype, 0);
	if (k == NULL)
	{
		return(NULL);
	}

	Py_RETURN_NONE;

	ossl_error:
		set_openssl_error("Error");
	fail:
		Py_XDECREF(k);
		return(NULL);
}

PyDoc_STRVAR(key_doc, "OpenSSL EVP_PKEY objects.");

static PyTypeObject
KeyType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	QPATH("Key"),                   /* tp_name */
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
	{
		Py_DECREF(tls);
		return(NULL);
	}
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

	cert->ossl_crt = PEM_read_X509(fp, NULL, password_parameter, &pwp);
	if (cert->ossl_crt == NULL)
		goto ossl_error;

	return((PyObj) cert);

	ossl_error:
		set_openssl_error("Error");
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
	 * The other variants are strings as well...
	 * The UTCTIME strings omit the century and millennium parts of the year.
	 */
	gt = ASN1_TIME_to_generalizedtime(t, NULL);
	rob = PyUnicode_FromStringAndSize(M_ASN1_STRING_data(gt), M_ASN1_STRING_length(gt));
	M_ASN1_GENERALIZEDTIME_free(gt);

	return(rob);
}

#define CERTIFICATE_PROPERTIES() \
	CERT_PROPERTY(not_before_string, \
		"The 'notBefore' field as a string.", X509_get_notBefore, str_from_asn1_time) \
	CERT_PROPERTY(not_after_string, \
		"The 'notAfter' field as a string.", X509_get_notAfter, str_from_asn1_time) \
	CERT_PROPERTY(signature_type, \
		"The type of used to sign the key.", X509_extract_key, key_from_ossl_key) \
	CERT_PROPERTY(subject, \
		"The subject data of the cerficate.", X509_get_subject_name, seq_from_names) \
	CERT_PROPERTY(public_key, \
		"The public key provided by the certificate.", X509_extract_key, key_from_ossl_key) \
	CERT_PROPERTY(version, \
		"The Format Version", X509_get_version, PyLong_FromLong)

#define CERT_PROPERTY(NAME, DOC, GET, CONVERT) \
	static PyObj certificate_get_##NAME(PyObj crt) \
	{ \
		certificate_t ossl_crt = ((Certificate) crt)->ossl_crt; \
		return(CONVERT(GET(ossl_crt))); \
	} \

	CERTIFICATE_PROPERTIES()
#undef CERT_PROPERTY

static PyObj
certificate_get_type(PyObj self)
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
		return(NULL); XCOVERAGE
	}

	cert->ossl_crt = load_pem_certificate(pem, password_parameter, &pwp);
	if (cert->ossl_crt == NULL)
		goto ossl_error;

	return((PyObj) cert);

	ossl_error:
		set_openssl_error("Error");
	fail:
		Py_XDECREF(cert);
		return(NULL);
}

PyDoc_STRVAR(certificate_doc, "OpenSSL X509 Certificate Objects");

static PyTypeObject
CertificateType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	QPATH("Certificate"),           /* tp_name */
	sizeof(struct Certificate),     /* tp_basicsize */
	0,                              /* tp_itemsize */
	certificate_dealloc,            /* tp_dealloc */
	NULL,                           /* tp_print */
	NULL,                           /* tp_getattr */
	NULL,                           /* tp_setattr */
	NULL,                           /* tp_compare */
	certificate_repr,               /* tp_repr */
	NULL,                           /* tp_as_number */
	NULL,                           /* tp_as_sequence */
	NULL,                           /* tp_as_mapping */
	NULL,                           /* tp_hash */
	NULL,                           /* tp_call */
	certificate_str,                /* tp_str */
	NULL,                           /* tp_getattro */
	NULL,                           /* tp_setattro */
	NULL,                           /* tp_as_buffer */
	Py_TPFLAGS_BASETYPE|
	Py_TPFLAGS_DEFAULT,             /* tp_flags */
	certificate_doc,                /* tp_doc */
	NULL,                           /* tp_traverse */
	NULL,                           /* tp_clear */
	NULL,                           /* tp_richcompare */
	0,                              /* tp_weaklistoffset */
	NULL,                           /* tp_iter */
	NULL,                           /* tp_iternext */
	certificate_methods,            /* tp_methods */
	certificate_members,            /* tp_members */
	certificate_getset,             /* tp_getset */
	NULL,                           /* tp_base */
	NULL,                           /* tp_dict */
	NULL,                           /* tp_descr_get */
	NULL,                           /* tp_descr_set */
	0,                              /* tp_dictoffset */
	NULL,                           /* tp_init */
	NULL,                           /* tp_alloc */
	certificate_new,                /* tp_new */
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
	{"rallocate", (PyCFunction) context_rallocate,
		METH_NOARGS, PyDoc_STR(
			"Allocate a TLS :py:class:`Transport` instance for "
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

	PyObj key_ob = NULL;
	PyObj certificates = NULL; /* iterable */
	PyObj requirements = NULL; /* iterable */

	char *ciphers = SHADE_OPENSSL_CIPHERS;
	char *protocol = "TLS";

	int allow_ssl_v2 = 0;

	if (!PyArg_ParseTupleAndKeywords(args, kw,
		"|OOOssp", kwlist,
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
	 * The key is checked and loaded later.
	 */
	ctx->tls_key_status = key_none;
	ctx->tls_context = NULL;

	if (requirements == NULL)
	{
		/* client positioning */

		#define X_TLS_METHOD(STRING, PREFIX) \
			else if (strcmp(STRING, protocol) == 0) \
			ctx->tls_context = SSL_CTX_new(PREFIX##_client_method());

			if (0)
			X_TLS_METHODS()

		#undef X_TLS_METHOD
	}
	else
	{
		/* server positioning */

		#define X_TLS_METHOD(STRING, PREFIX) \
			else if (strcmp(STRING, protocol) == 0) \
				ctx->tls_context = SSL_CTX_new(PREFIX##_server_method());

			if (0)
			X_TLS_METHODS()

		#undef X_TLS_METHOD
	}

	if (ctx->tls_context == NULL)
	{
		/* XXX: check for openssl failure */

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
		/* No, SSL_OP_NO_SSLv2 defined by openssl headers */
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

		key = load_pem_private_key(key_ob, password_parameter, &pwp);
		if (key == NULL)
		{
			goto ossl_error;
		}

		if (SSL_CTX_use_PrivateKey(ctx->tls_context, key)
				&& SSL_CTX_check_private_key(ctx->tls_context))
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
	{
		Py_XDECREF(ctx);
		return(NULL);
	}
}

PyDoc_STRVAR(context_doc,
	"OpenSSL transport security context.");

static PyTypeObject
ContextType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	QPATH("Context"),                /* tp_name */
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
 * Write enciphered protocol data into the transport.
 * Either for deciphered reads or for internal protocol management.
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

/*
 * Read deciphered data from the transport.
 */
static PyObj
transport_read_deciphered(PyObj self, PyObj buffer)
{
	Transport tls = (Transport) self;
	Py_buffer pb;
	int xfer;

	if (PyObject_GetBuffer(buffer, &pb, PyBUF_WRITABLE))
		return(NULL);

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

/*
 * Write deciphered data to be sent to the remote end.
 */
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
transport_pending(PyObj self)
{
	Transport tls = (Transport) self;
	int nbytes;
	PyObj rob;

	nbytes = SSL_pending(tls->tls_state);
	rob = PyLong_FromLong((long) nbytes);

	return(rob);
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
			"Get the transport's status. XXX: ambiguous docs"
		)
	},

	{"leak_session", (PyCFunction) transport_leak_session,
		METH_NOARGS, PyDoc_STR(
			"Force the transport's session to be leaked regardless of its shutdown state.\n"
			"`<http://www.openssl.org/docs/ssl/SSL_set_shutdown.html>`_"
		)
	},

	{"pending", (PyCFunction) transport_pending,
		METH_NOARGS, PyDoc_STR(
			"Return the number of bytes available for reading."
		)
	},

	{"terminate", (PyCFunction) transport_terminate,
		METH_NOARGS, PyDoc_STR(
			"Initiate the shutdown sequence for the TLS state. "
			"Enciphered reads and writes must be performed in order to complete the sequence."
		)
	},

	{"read_enciphered", (PyCFunction) transport_read_enciphered,
		METH_O, PyDoc_STR(
			"Get enciphered data to be written to the remote endpoint. "
			"Transfer to be written.\n"
		)
	},

	{"write_enciphered", (PyCFunction) transport_write_enciphered,
		METH_O, PyDoc_STR(
			"Put enciphered data into the TLS channel to be later "
			"decrypted and retrieved with read_deciphered.\n"
		)
	},

	{"read_deciphered", (PyCFunction) transport_read_deciphered,
		METH_O, PyDoc_STR(
			"read_deciphered()\n\n"
			"Get decrypted data from the TLS channel for processing by the local endpoint."
		)
	},

	{"write_deciphered", (PyCFunction) transport_write_deciphered,
		METH_O, PyDoc_STR(
			"Put decrypted data into the TLS channel to be "
			"sent to the remote endpoint after encryption."
		)
	},

	{NULL,},
};

static PyMemberDef
transport_members[] = {
	{"error", T_OBJECT,
		offsetof(struct Transport, tls_protocol_error), READONLY,
		PyDoc_STR(
			"Protocol error data. :py:obj:`None` if no *protocol* error occurred."
		)
	},

	{"pending_enciphered_writes", T_ULONG,
		offsetof(struct Transport, tls_pending_writes), READONLY,
		PyDoc_STR(
			"Snapshot of the Transport's out-going buffer used for writing. "
			"Growth indicates need for lower-level write."
		)
	},

	{"pending_enciphered_reads", T_ULONG,
		offsetof(struct Transport, tls_pending_reads), READONLY,
		PyDoc_STR(
			"Snapshot of the Transport's incoming buffer used for reading. "
			"Growth indicates need for higher-level read attempt.")
	},

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

static PyObj
transport_get_terminated(PyObj self, void *_)
{
	Transport tls = (Transport) self;

	if (SSL_RECEIVED_SHUTDOWN & SSL_get_shutdown(tls->tls_state))
	{
		Py_INCREF(Py_True);
		return(Py_True);
	}

	Py_INCREF(Py_False);
	return(Py_False);
}

static PyGetSetDef transport_getset[] = {
	{"protocol", transport_get_protocol, NULL,
		PyDoc_STR(
			"The protocol used by the Transport.\n"
		)
	},

	{"peer_certificate", transport_get_peer_certificate, NULL,
		PyDoc_STR(
			"Get the peer certificate. If the Transport has yet to receive it, "
			":py:obj:`None` will be returned."
		)
	},

	{"terminated", transport_get_terminated, NULL,
		PyDoc_STR("Whether the shutdown state has been *received*.")
	},
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

PyDoc_STRVAR(transport_doc, "OpenSSL Secure Transfer State.");

static PyTypeObject
TransportType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	QPATH("Transport"),             /* tp_name */
	sizeof(struct Transport),       /* tp_basicsize */
	0,                              /* tp_itemsize */
	transport_dealloc,              /* tp_dealloc */
	NULL,                           /* tp_print */
	NULL,                           /* tp_getattr */
	NULL,                           /* tp_setattr */
	NULL,                           /* tp_compare */
	transport_repr,                 /* tp_repr */
	NULL,                           /* tp_as_number */
	NULL,                           /* tp_as_sequence */
	NULL,                           /* tp_as_mapping */
	NULL,                           /* tp_hash */
	NULL,                           /* tp_call */
	NULL,                           /* tp_str */
	NULL,                           /* tp_getattro */
	NULL,                           /* tp_setattro */
	NULL,                           /* tp_as_buffer */
	Py_TPFLAGS_BASETYPE|
	Py_TPFLAGS_DEFAULT,             /* tp_flags */
	transport_doc,                  /* tp_doc */
	NULL,                           /* tp_traverse */
	NULL,                           /* tp_clear */
	NULL,                           /* tp_richcompare */
	0,                              /* tp_weaklistoffset */
	NULL,                           /* tp_iter */
	NULL,                           /* tp_iternext */
	transport_methods,              /* tp_methods */
	transport_members,              /* tp_members */
	transport_getset,               /* tp_getset */
	NULL,                           /* tp_base */
	NULL,                           /* tp_dict */
	NULL,                           /* tp_descr_get */
	NULL,                           /* tp_descr_set */
	0,                              /* tp_dictoffset */
	NULL,                           /* tp_init */
	NULL,                           /* tp_alloc */
	transport_new,                  /* tp_new */
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
			"Returns None. XXX: Remove?"
		)
	},
	{NULL,}
};

#define PYTHON_TYPES() \
	ID(Key) \
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
	 * Initialize types.
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
#if 0
"""
#endif