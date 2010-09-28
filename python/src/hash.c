#include <Python.h>
#include <cyfer/hash.h>

#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif

staticforward PyTypeObject HashType;

typedef struct {
	PyObject_HEAD;
	CYFER_HASH_CTX *ctx;
	size_t mdlen;
} HashObject;

static PyObject *supported(PyObject *self, PyObject *args)
{
	int i;
	PyObject *list, *val;
	CYFER_Hash_t *CYFER_HashTypes;	
	
	if (!PyArg_ParseTuple(args, ":Supported")) return NULL;

	CYFER_HashTypes = CYFER_Hash_Get_Supported();
	
	list = PyList_New(0);
	for (i = 0; CYFER_HashTypes[i].name; i++) {
		val = Py_BuildValue("s", CYFER_HashTypes[i].name);
		PyList_Append(list, val);
	}
	return list;
}

static PyObject *size(PyObject *self, PyObject *args)
{
	char *name;
	size_t mdlen;
	int type = CYFER_HASH_NONE;

	if (!PyArg_ParseTuple(args, "s:Size", &name)) return NULL;
	if (name) type = CYFER_Hash_Select(name, &mdlen);
	if (type == CYFER_HASH_NONE) {
		PyErr_SetString(PyExc_ValueError, "unsupported hash algorithm");
		return NULL;
	}

	return Py_BuildValue("l", mdlen);
}

static int init(PyObject *self, PyObject *args, PyObject *kwargs)
{
	HashObject *hash;
	char *name;
	int type = CYFER_HASH_NONE;
	size_t mdlen;

	hash = (HashObject *) self;

	if (!PyArg_ParseTuple(args, "s:Hash", &name)) return -1;
	if (name) type = CYFER_Hash_Select(name, &mdlen);
	if (type == CYFER_HASH_NONE) {
		PyErr_SetString(PyExc_ValueError, "unsupported hash algorithm");
		return -1;
	}

	hash->mdlen = mdlen;
	hash->ctx = CYFER_Hash_Init(type);
	if (!hash->ctx) {
		Py_DECREF(hash);
		PyErr_SetString(PyExc_MemoryError, "out of memory");
		return -1;
	}
	return 0;
}

static PyObject *new(PyTypeObject *objtype, PyObject *args, PyObject *kwargs)
{
	HashObject *obj = PyObject_New(HashObject, &HashType);

	obj->mdlen = 0;
	obj->ctx = NULL;

	return (PyObject *) obj;
}

static PyObject *update(HashObject *self, PyObject *args)
{
	unsigned char *data;
	size_t len;

	if (!PyArg_ParseTuple(args, "s#:Update", &data, &len)) return NULL;

	if (!self->ctx) {
		PyErr_SetString(PyExc_AssertionError, "algorithm has already finished");
		return NULL;
	}

	CYFER_Hash_Update(self->ctx, data, len);

	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *finish(HashObject *self, PyObject *args)
{
	unsigned char *data;

	if (!PyArg_ParseTuple(args, ":Finish")) return NULL;

	if (!self->ctx) {
		PyErr_SetString(PyExc_AssertionError, "algorithm has already finished");
		return NULL;
	}
	data = alloca(self->mdlen);
	CYFER_Hash_Finish(self->ctx, data);

	self->ctx = NULL;

	return Py_BuildValue("s#", data, self->mdlen);
}

static void hash_dealloc(PyObject *self)
{
	HashObject *hash;
	unsigned char *dummy;
	
	hash = (HashObject *) self;
	
	if (hash->ctx) {
		dummy = alloca(hash->mdlen);
		CYFER_Hash_Finish(hash->ctx, dummy);
	}
	PyObject_Del(self);
}

static PyMethodDef HashMethods[] = {
	{ "Supported", supported, METH_VARARGS, "List supported hash algorithms." },
	{ "Size", size, METH_VARARGS, "Return hash length for given algorithm." },
    {NULL, NULL, 0, NULL}
};

static PyMethodDef HashTypeMethods[] = {
	{ "Update", (PyCFunction) update, METH_VARARGS, "Update hash value." },
	{ "Finish", (PyCFunction) finish, METH_VARARGS, "Finalize computation, return hash value and destroy Hash object." },
    {NULL, NULL, 0, NULL}
};

static PyTypeObject HashType = {
	PyObject_HEAD_INIT(NULL)
	0,
	"hash.Hash",
	sizeof(HashObject),
	0,
	hash_dealloc
};

void inithash(void)
{
	PyObject *module;

	HashType.ob_type = &PyType_Type;
	HashType.tp_methods = HashTypeMethods;
	HashType.tp_flags = Py_TPFLAGS_DEFAULT;
	HashType.tp_new = new;
	HashType.tp_init = init;

	if (PyType_Ready(&HashType) < 0) return;

	module = Py_InitModule("cyfer.hash", HashMethods);

	PyModule_AddObject(module, "Hash", (PyObject *)&HashType);
}

