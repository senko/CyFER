#include <Python.h>
#include <cyfer/pk.h>
#include <string.h>

#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif

staticforward PyTypeObject PkType;

typedef struct {
	PyObject_HEAD;
	CYFER_PK_CTX *ctx;
} PkObject;

#define BLOCK_CREATE(x, len) x = alloca(len)
#define BLOCK_CREATE_ZERO(x, len) x = alloca(len); memset(x, 0, len)
#define BLOCK_CREATE_FROM(x, len, img, imglen) \
	x = alloca(len); memset(x, 0, len); memcpy(x, img, (len > imglen) ? imglen : len)

#define CHECK_INIT if (!self->ctx) { PyErr_SetString(PyExc_AssertionError, "algorithm is not initialized"); return NULL; }

static PyObject *supported(PyObject *self, PyObject *args)
{
	int i;
	PyObject *list, *val;
	CYFER_Pk_t *CYFER_PkAlgorithms;

	if (!PyArg_ParseTuple(args, ":Supported")) return NULL;

	CYFER_PkAlgorithms = CYFER_Pk_Get_Supported();
	list = PyList_New(0);
	for (i = 0; CYFER_PkAlgorithms[i].name; i++) {
		val = Py_BuildValue("s", CYFER_PkAlgorithms[i].name);
		PyList_Append(list, val);
	}
	return list;
}

static int init(PyObject *self, PyObject *args, PyObject *kwargs)
{
	PkObject *pk;
	char *name;
	bool enc, sig;
	int type = CYFER_PK_NONE;

	pk = (PkObject *) self;

	if (!PyArg_ParseTuple(args, "s:Pk", &name)) return -1;
	if (name) type = CYFER_Pk_Select(name, &enc, &sig);
	if (type == CYFER_PK_NONE) {
		PyErr_SetString(PyExc_ValueError, "unsupported public-key algorithm");
		return -1;
	}

	pk->ctx = CYFER_Pk_Init(type);
	if (!pk->ctx) {
		Py_DECREF(pk);
		PyErr_SetString(PyExc_MemoryError, "out of memory");
		return -1;
	}

	return 0;
}

static PyObject *new(PyTypeObject *objtype, PyObject *args, PyObject *kwargs)
{
	PkObject *obj = PyObject_New(PkObject, &PkType);
	obj->ctx = NULL;
	return (PyObject *) obj;
}


static PyObject *generate_key(PkObject *self, PyObject *args)
{
	size_t size;

	if (!PyArg_ParseTuple(args, "l:GenerateKey", &size)) return NULL;
	CHECK_INIT;
	CYFER_Pk_Generate_Key(self->ctx, size);
	Py_INCREF(Py_None);
	return Py_None;
}	

static PyObject *keysize(PkObject *self, PyObject *args)
{
	size_t privlen, publen;

	if (!PyArg_ParseTuple(args, ":KeySize")) return NULL;
	CHECK_INIT;
	CYFER_Pk_KeySize(self->ctx, &privlen, &publen);
	return Py_BuildValue("(ll)", privlen, publen);
}

static PyObject *size(PkObject *self, PyObject *args)
{
	size_t pt_len, ct_len;

	if (!PyArg_ParseTuple(args, ":Size")) return NULL;
	CYFER_Pk_Size(self->ctx, &pt_len, &ct_len);
	return Py_BuildValue("(ll)", pt_len, ct_len);
}

static PyObject *export_key(PkObject *self, PyObject *args)
{
	size_t privlen, publen;
	unsigned char *priv, *pub;

	if (!PyArg_ParseTuple(args, ":ExportKey")) return NULL;
	CHECK_INIT;
	
	CYFER_Pk_KeySize(self->ctx, &privlen, &publen);
	BLOCK_CREATE(priv, privlen);
	BLOCK_CREATE(pub, publen);
	CYFER_Pk_Export_Key(self->ctx, priv, pub);
	return Py_BuildValue("(s#s#)", priv, privlen, pub, publen);
}

static PyObject *import_key(PkObject *self, PyObject *args)
{
	size_t privlen, publen;
	unsigned char *priv, *pub;

	if (!PyArg_ParseTuple(args, "z#z#:ImportKey", &priv, &privlen, &pub, &publen)) return NULL;
	CHECK_INIT;

	CYFER_Pk_Import_Key(self->ctx, priv, privlen, pub, publen);
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *pk_encrypt(PkObject *self, PyObject *args)
{
	unsigned char *s, *in, *out;
	size_t pt_len, ct_len;
	size_t s_len;

	if (!PyArg_ParseTuple(args, "s#:Encrypt", &s, &s_len)) return NULL;

	CYFER_Pk_Size(self->ctx, &pt_len, &ct_len);
	CHECK_INIT;

	BLOCK_CREATE_FROM(in, pt_len, s, s_len);
	BLOCK_CREATE(out, ct_len);
	CYFER_Pk_Encrypt(self->ctx, in, out);
	return Py_BuildValue("s#", out, ct_len);
}

static PyObject *pk_decrypt(PkObject *self, PyObject *args)
{
	unsigned char *s, *in, *out;
	size_t pt_len, ct_len;
	size_t s_len;

	if (!PyArg_ParseTuple(args, "s#:Decrypt", &s, &s_len)) return NULL;
	CHECK_INIT;

	CYFER_Pk_Size(self->ctx, &pt_len, &ct_len);
	BLOCK_CREATE_FROM(in, ct_len, s, s_len);
	BLOCK_CREATE(out, pt_len);
	CYFER_Pk_Decrypt(self->ctx, in, out);
	return Py_BuildValue("s#", out, pt_len);
}

static PyObject *pk_sign(PkObject *self, PyObject *args)
{
	unsigned char *s, *in, *out;
	size_t pt_len, ct_len;
	size_t s_len;

	if (!PyArg_ParseTuple(args, "s#:Sign", &s, &s_len)) return NULL;
	CHECK_INIT;

	CYFER_Pk_Size(self->ctx, &pt_len, &ct_len);
	BLOCK_CREATE_FROM(in, pt_len, s, s_len);
	BLOCK_CREATE(out, ct_len);
	CYFER_Pk_Sign(self->ctx, in, out);
	return Py_BuildValue("s#", out, ct_len);
}

static PyObject *pk_verify(PkObject *self, PyObject *args)
{
	unsigned char *s, *t, *in, *out;
	size_t pt_len, ct_len;
	size_t s_len, t_len;

	if (!PyArg_ParseTuple(args, "s#s#:Verify", &s, &s_len, &t, &t_len)) return NULL;
	CHECK_INIT;

	CYFER_Pk_Size(self->ctx, &pt_len, &ct_len);
	BLOCK_CREATE_FROM(in, ct_len, s, s_len);
	BLOCK_CREATE_FROM(out, pt_len, t, t_len);
	return Py_BuildValue("i", CYFER_Pk_Verify(self->ctx, in, out));
}

static void pk_dealloc(PyObject *self)
{
	PkObject *cipher;
	
	cipher = (PkObject *) self;
	if (cipher->ctx) {
		CYFER_Pk_Finish(cipher->ctx);
	}
	PyObject_Del(self);
}

static PyMethodDef PkTypeMethods[] = {
	{ "GenerateKey", (PyCFunction) generate_key, METH_VARARGS, "Generate a new key pair." },
	{ "KeySize", (PyCFunction) keysize, METH_VARARGS, "Return private and public key sizes." },
	{ "Size", (PyCFunction) size, METH_VARARGS, "Return plaintext and ciphertext block sizes." },
	{ "ExportKey", (PyCFunction) export_key, METH_VARARGS, "Export key pair." },
	{ "ImportKey", (PyCFunction) import_key, METH_VARARGS, "Import key pair." },
	{ "Encrypt", (PyCFunction) pk_encrypt, METH_VARARGS, "Encrypt block of data using public key." },
	{ "Decrypt", (PyCFunction) pk_decrypt, METH_VARARGS, "Decrypt block of data using private key." },
	{ "Sign", (PyCFunction) pk_sign, METH_VARARGS, "Sign block of data using public key." },
	{ "Verify", (PyCFunction) pk_verify, METH_VARARGS, "Verify data signature." },
    {NULL, NULL, 0, NULL}
};

#if 0
static PyObject *pk_getattr(PkObject *obj, char *name)
{
	return Py_FindMethod(PkTypeMethods, (PyObject *) obj, name);
}
#endif

static PyTypeObject PkType = {
	PyObject_HEAD_INIT(NULL)
	0,
	"pk.Pk",
	sizeof(PkObject),
	0,
	pk_dealloc,
};

static PyMethodDef PkMethods[] = {
	{ "Supported", supported, METH_VARARGS, "List supported public-key algorithms." },
    {NULL, NULL, 0, NULL}
};

void initpk(void)
{
	PyObject *module;

	PkType.ob_type = &PyType_Type;
	PkType.tp_methods = PkTypeMethods;
	PkType.tp_flags = Py_TPFLAGS_DEFAULT;
	PkType.tp_new = new;
	PkType.tp_init = init;

	if (PyType_Ready(&PkType) < 0) return;

	module = Py_InitModule("cyfer.pk", PkMethods);

	PyModule_AddObject(module, "Pk", (PyObject *)&PkType);

}

