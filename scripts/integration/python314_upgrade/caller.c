// SPDX-License-Identifier: MIT
#include <Python.h>
#if PY_VERSION_HEX != 0x030e07f0
#error Historical caller must compile with the exact Python 3.14.7 headers
#endif
static PyObject *identity(PyObject *self, PyObject *unused) {
    (void)self; (void)unused;
    PyObject *list = Py_BuildValue("[iii]", 2, 5, -3);
    if (!list) return NULL;
    long sum = 0;
    for (Py_ssize_t i = 0; i < PyList_GET_SIZE(list); i++)
        sum += PyLong_AsLong(PyList_GET_ITEM(list, i));
    Py_DECREF(list);
    return Py_BuildValue("(ssl)", PY_VERSION, Py_GetVersion(), sum);
}
static PyMethodDef methods[] = {{"identity", identity, METH_NOARGS, NULL}, {NULL, NULL, 0, NULL}};
static struct PyModuleDef module = {PyModuleDef_HEAD_INIT, "historical_caller", NULL, -1, methods, NULL, NULL, NULL, NULL};
PyMODINIT_FUNC PyInit_historical_caller(void) { return PyModule_Create(&module); }
