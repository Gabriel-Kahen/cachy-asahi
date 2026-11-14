// SPDX-License-Identifier: MIT
#define Py_LIMITED_API 0x030b0000
#include <Python.h>
#if PY_VERSION_HEX != 0x030e08f0
#error This consumer requires the selected Python 3.14.8 headers
#endif

static PyObject *total(PyObject *self, PyObject *items) {
    (void)self;
    Py_ssize_t size = PySequence_Size(items);
    if (size < 0) return NULL;
    long sum = 0;
    for (Py_ssize_t i = 0; i < size; i++) {
        PyObject *item = PySequence_GetItem(items, i);
        if (!item) return NULL;
        long value = PyLong_AsLong(item);
        Py_DECREF(item);
        if (PyErr_Occurred()) return NULL;
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
    {"total", total, METH_O, "Sum a bounded integer sequence through limited API."},
    {"versions", versions, METH_NOARGS, "Compile/runtime versions."},
    {NULL, NULL, 0, NULL}
};
static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT, "consumer_stable", NULL, -1, methods,
    NULL, NULL, NULL, NULL
};
PyMODINIT_FUNC PyInit_consumer_stable(void) { return PyModule_Create(&module); }
