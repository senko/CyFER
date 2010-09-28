#include <Python.h>
#include <cyfer/keyex.h>
#include <string.h>

#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif

staticforward PyTypeObject KeyExType;

typedef struct {
	PyObject_HEAD;
	CYFER_KEYEX_CTX *ctx;
} KeyExObject;

#define BLOCK_CREATE(x, len) x = alloca(len)
#define BLOCK_CREATE_ZERO(x, len) x = alloca(len); memset(x, 0, len)
#define BLOCK_CREATE_FROM(x, len, img, imglen) \
	x = alloca(len); memset(x, 0, len); memcpy(x, img, (len > imglen) ? imglen : len)

#define CHECK_INIT if (!self->ctx) { PyErr_SetString(PyExc_AssertionError, "algorithm is not initialized"); return NULL; }

static PyObject *supported(PyObject *self, PyObject *args)
{
	int i;
	PyObject *list, *val;
	CYFER_KeyEx_t *CYFER_KeyExAlgorithms;

	if (!PyArg_ParseTuple(args, ":Supported")) return NULL;

	CYFER_KeyExAlgorithms = CYFER_KeyEx_Get_Supported();
	list = PyList_New(0);
	for (i = 0; CYFER_KeyExAlgorithms[i].name; i++) {
		val = Py_BuildValue("s", CYFER_KeyExAlgorithms[i].name);
		PyList_Append(list, val);
	}
	return list;
}

static int init(PyObject *self, PyObject *args, PyObject *kwargs)
{
	KeyExObject *keyex;
	char *name;
	int type = CYFER_KEYEX_NONE;

	keyex = (KeyExObject *) self;

	if (!PyArg_ParseTuple(args, "s:KeyEx", &name)) return -1;
	if (name) type = CYFER_KeyEx_Select(name);
	if (type == CYFER_KEYEX_NONE) {
		PyErr_SetString(PyExc_ValueError, "unsupported key-exchange algorithm");
		return -1;
	}

	keyex->ctx = CYFER_KeyEx_Init(type);
	if (!keyex->ctx) {
		Py_DECREF(keyex);
		PyErr_SetString(PyExc_MemoryError, "out of memory");
		return -1;
	}

	return 0;
}

static PyObject *new(PyTypeObject *objtype, PyObject *args, PyObject *kwargs)
{
	KeyExObject *obj = PyObject_New(KeyExObject, &KeyExType);
	obj->ctx = NULL;
	return (PyObject *) obj;
}


static PyObject *generate_key(KeyExObject *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ":GenerateKey")) return NULL;
	CHECK_INIT;
	CYFER_KeyEx_Generate_Key(self->ctx);
	Py_INCREF(Py_None);
	return Py_None;
}	

static PyObject *keysize(KeyExObject *self, PyObject *args)
{
	size_t privlen, publen;

	if (!PyArg_ParseTuple(args, ":KeySize")) return NULL;
	CHECK_INIT;
	CYFER_KeyEx_KeySize(self->ctx, &privlen, &publen);
	return Py_BuildValue("(ll)", privlen, publen);
}

static PyObject *compute_key(KeyExObject *self, PyObject *args)
{
	size_t publen;
	unsigned char *pub;

	if (!PyArg_ParseTuple(args, "s#:ComputeKey", &pub, &publen)) return NULL;
	CHECK_INIT;
	CYFER_KeyEx_Compute_Key(self->ctx, pub, publen);
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *public_key(KeyExObject *self, PyObject *args)
{
	size_t privlen, publen;
	unsigned char *pub;

	if (!PyArg_ParseTuple(args, ":PublicKey")) return NULL;
	CHECK_INIT;
	CYFER_KeyEx_KeySize(self->ctx, &privlen, &publen);

	BLOCK_CREATE(pub, publen);
	CYFER_KeyEx_Public_Key(self->ctx, pub);
	return Py_BuildValue("s#", pub, publen);
}

static PyObject *shared_key(KeyExObject *self, PyObject *args)
{
	size_t len;
	unsigned char *data;

	if (!PyArg_ParseTuple(args, "l:SharedKey", &len)) return NULL;
	CHECK_INIT;

	BLOCK_CREATE(data, len);
	CYFER_KeyEx_Shared_Key(self->ctx, data, len);
	return Py_BuildValue("s#", data, len);
}

static void keyex_dealloc(PyObject *self)
{
	KeyExObject *cipher;
	
	cipher = (KeyExObject *) self;
	if (cipher->ctx) {
		CYFER_KeyEx_Finish(cipher->ctx);
	}
	PyObject_Del(self);
}

static PyMethodDef KeyExTypeMethods[] = {
	{ "GenerateKey", (PyCFunction) generate_key, METH_VARARGS, "Generate a new key pair." },
	{ "KeySize", (PyCFunction) keysize, METH_VARARGS, "Return private and public key sizes." },
	{ "ComputeKey", (PyCFunction) compute_key, METH_VARARGS, "Compute shared key." },
	{ "PublicKey", (PyCFunction) public_key, METH_VARARGS, "Export public key." },
	{ "SharedKey", (PyCFunction) shared_key, METH_VARARGS, "Return shared key." },
    {NULL, NULL, 0, NULL}
};

#if 0
static PyObject *keyex_getattr(KeyExObject *obj, char *name)
{
	return Py_FindMethod(KeyExTypeMethods, (PyObject *) obj, name);
}
#endif

static PyTypeObject KeyExType = {
	PyObject_HEAD_INIT(NULL)
	0,
	"keyex.KeyEx",
	sizeof(KeyExObject),
	0,
	keyex_dealloc,
};

static PyMethodDef KeyExMethods[] = {
	{ "Supported", supported, METH_VARARGS, "List supported key-exchange algorithms." },
    {NULL, NULL, 0, NULL}
};

void initkeyex(void)
{
	PyObject *module;

	KeyExType.ob_type = &PyType_Type;
	KeyExType.tp_methods = KeyExTypeMethods;
	KeyExType.tp_flags = Py_TPFLAGS_DEFAULT;
	KeyExType.tp_new = new;
	KeyExType.tp_init = init;

	if (PyType_Ready(&KeyExType) < 0) return;

	module = Py_InitModule("cyfer.keyex", KeyExMethods);

	PyModule_AddObject(module, "KeyEx", (PyObject *)&KeyExType);

}

