// SPDX-License-Identifier: MIT
#include <Python.h>
#if PY_VERSION_HEX != 0x030e08f0
#error This consumer requires the selected Python 3.14.8 headers
#endif

static PyObject *total(PyObject *self, PyObject *items) {
    (void)self;
    if (!PyList_Check(items)) {
        PyErr_SetString(PyExc_TypeError, "list required");
        return NULL;
    }
    /* Full-API list macros deliberately exercise the cp314 build. */
    long sum = 0;
    for (Py_ssize_t i = 0; i < PyList_GET_SIZE(items); i++) {
        long value = PyLong_AsLong(PyList_GET_ITEM(items, i));
        if (PyErr_Occurred()) return NULL;
        /* The fixture uses small bounded integers, avoiding signed overflow. */
        if (value < -1000 || value > 1000 || sum < -100000 || sum > 100000) {
            PyErr_SetString(PyExc_ValueError, "fixture bounds exceeded");
            return NULL;
        }
        sum += value;
    }
    return PyLong_FromLong(sum);
}

static PyObject *versions(PyObject *self, PyObject *unused) {
    (void)self; (void)unused;
    return Py_BuildValue("(ss)", PY_VERSION, Py_GetVersion());
}

static PyMethodDef methods[] = {
    {"total", total, METH_O, "Sum a bounded integer list."},
    {"versions", versions, METH_NOARGS, "Compile/runtime versions."},
    {NULL, NULL, 0, NULL}
};
static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT, "consumer_full", NULL, -1, methods,
    NULL, NULL, NULL, NULL
};
PyMODINIT_FUNC PyInit_consumer_full(void) { return PyModule_Create(&module); }
