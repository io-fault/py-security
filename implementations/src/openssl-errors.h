/*
	// OpenSSL library error.
*/
#define EData_STRINGS() \
	X(message) \
	X(data) \
	X(library) \
	X(file) \
	X(function)

struct EData {
	PyObject_HEAD
	unsigned long errcode;
	PyObj errmessage;
	PyObj errdata;
	PyObj errlibrary;
	PyObj errfile;
	PyObj errfunction;
	int errline;
};

typedef struct EData *EData;

static void
edata_dealloc(PyObj self)
{
	EData e = (EData) self;
	Py_ssize_t i, n = Py_SIZE(self);

	#define X(FIELD) \
		Py_XDECREF(e->err##FIELD); \
		e->err##FIELD = NULL; \

		EData_STRINGS()
	#undef X

	Py_TYPE(self)->tp_free(self);
}

static PyMemberDef
edata_members[] = {
	#define X(FIELD) \
		{#FIELD, T_OBJECT, \
			offsetof(struct EData, err##FIELD), READONLY, NULL\
		},

		EData_STRINGS()
	#undef X

	{"line", T_INT,
		offsetof(struct EData, errline), READONLY, NULL
	},
	{"code", T_INT,
		offsetof(struct EData, errcode), READONLY, NULL
	},
	{NULL},
};

static PyObj
edata_richcompare(PyObj self, PyObj x, int op)
{
	EData a = (EData) self, b = (EData) x;
	PyObj rob;

	if (self->ob_type != x->ob_type)
	{
		Py_INCREF(Py_NotImplemented);
		return(Py_NotImplemented);
	}

	switch (op)
	{
		case Py_NE:
			if (a->errcode != b->errcode)
			{
				rob = Py_False;
				Py_INCREF(rob);
			}
		case Py_EQ:
			if (a->errcode == b->errcode)
			{
				rob = Py_True;
				Py_INCREF(rob);
			}
		break;

		default:
			PyErr_SetString(PyExc_TypeError, "EData only supports equality");
			rob = NULL;
		break;
	}

	return(rob);
}

static PyObj
edata_str(PyObj self)
{
	const char *no_msg = "no description provided by implementation";
	EData e = (EData) self;
	PyObj rob;

	rob = PyUnicode_FromFormat("[%x] %V", e->errcode, e->errmessage, no_msg);
	return(rob);
}

static long
edata_hash(PyObj self)
{
	return ((EData) self)->errcode;
}

PyObj
edata_new(PyTypeObject *subtype, PyObj args, PyObj kw)
{
	static char *kwlist[] = {"code", "file", "line", "data", NULL,};
	PyObj file = NULL, data = NULL, rob;
	unsigned long code, line = 0;
	const char *library, *function, *message;
	EData e;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "k|O!kO!", kwlist,
			&code,
			&PyUnicode_Type,
			&file,
			&line,
			&PyUnicode_Type,
			&data))
		return(NULL);

	rob = subtype->tp_alloc(subtype, 0);
	if (rob == NULL)
		return(NULL);

	e = (EData) rob;
	e->errcode = code;
	e->errline = line;

	e->errfile = file;
	Py_XINCREF(file);
	e->errdata = data;
	Py_XINCREF(data);

	library = ERR_lib_error_string(code);
	function = ERR_func_error_string(code);
	message = ERR_reason_error_string(code);

	if (message == NULL || message[0] == '\0')
		e->errmessage = NULL;
	else
	{
		e->errmessage = PyUnicode_FromString(message);
		if (e->errmessage == NULL)
			goto error;
	}

	if (library == NULL || library[0] == '\0')
		e->errlibrary = NULL;
	else
	{
		e->errlibrary = PyUnicode_FromString(library);
		if (e->errlibrary == NULL)
			goto error;
	}

	if (function == NULL || function[0] == '\0')
		e->errfunction = NULL;
	else
	{
		e->errfunction = PyUnicode_FromString(function);
		if (e->errfunction == NULL)
			goto error;
	}

	return(rob);

	error:
	{
		Py_DECREF(rob);
		return(NULL);
	}
}

PyDoc_STRVAR(edata_doc, "Error data storage for IError exceptions.");

PyTypeObject
EDataType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	PYTHON_MODULE_PATH("EData"),    /* tp_name */
	sizeof(struct EData),           /* tp_basicsize */
	0,                              /* tp_itemsize */
	edata_dealloc,                  /* tp_dealloc */
	NULL,                           /* tp_print */
	NULL,                           /* tp_getattr */
	NULL,                           /* tp_setattr */
	NULL,                           /* tp_compare */
	NULL,                           /* tp_repr */
	NULL,                           /* tp_as_number */
	NULL,                           /* tp_as_sequence */
	NULL,                           /* tp_as_mapping */
	edata_hash,                     /* tp_hash */
	NULL,                           /* tp_call */
	edata_str,                      /* tp_str */
	NULL,                           /* tp_getattro */
	NULL,                           /* tp_setattro */
	NULL,                           /* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,             /* tp_flags */
	edata_doc,                      /* tp_doc */
	NULL,                           /* tp_traverse */
	NULL,                           /* tp_clear */
	edata_richcompare,              /* tp_richcompare */
	0,                              /* tp_weaklistoffset */
	NULL,                           /* tp_iter */
	NULL,                           /* tp_iternext */
	NULL,                           /* tp_methods */
	edata_members,                  /* tp_members */
	NULL,                           /* tp_getset */
	NULL,                           /* tp_base */
	NULL,                           /* tp_dict */
	NULL,                           /* tp_descr_get */
	NULL,                           /* tp_descr_set */
	0,                              /* tp_dictoffset */
	NULL,                           /* tp_init */
	NULL,                           /* tp_alloc */
	edata_new,                      /* tp_new */
};

/**
	// OpenSSL uses a per-thread error queue.
*/
static PyObj
openssl_error_pop(void)
{
	EData err;
	PyObj rob;

	unsigned long code, line, flags = 0;
	const char *file = NULL;
	const char *data = NULL;
	const char *function = NULL;
	const char *message = NULL;
	const char *library = NULL;

	code = ERR_get_error_line_data(&file, &line, &data, &flags);

	rob = EDataType.tp_alloc(&EDataType, 0);
	if (rob == NULL)
		return(NULL);
	err = (EData) rob;

	library = ERR_lib_error_string(code);
	function = ERR_func_error_string(code);
	message = ERR_reason_error_string(code);

	err->errcode = code;
	err->errline = line;

	#define X(FIELD) \
		if (FIELD == NULL || FIELD[0] == '\0') \
			err->err##FIELD = NULL; \
		else \
		{ \
			err->err##FIELD = PyUnicode_FromString(FIELD); \
			if (err->err##FIELD == NULL) \
				goto error; \
		}

		EData_STRINGS()
	#undef X

	return(rob);

	error:
	{
		Py_DECREF(rob);
		return(NULL);
	}
}

static PyObj
openssl_error_stack(void)
{
	PyObj stack = NULL;

	stack = PyList_New(0);
	if (stack == NULL)
		return(NULL);

	while (ERR_peek_error() != 0)
	{
		PyObj ie = openssl_error_pop();
		if (ie == NULL)
		{
			Py_DECREF(stack);
			return(NULL);
		}
		PyList_Append(stack, ie);
	}

	return(stack);
}

extern PyObj PyExc_TransportSecurityError;

static void
openssl_error_set(void)
{
	PyObj val;
	val = openssl_error_pop();
	if (val)
		PyErr_SetObject(PyExc_TransportSecurityError, val);
}
