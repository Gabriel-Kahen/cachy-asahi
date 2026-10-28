// SPDX-License-Identifier: MIT
#define PY_SSIZE_T_CLEAN
#include <Python.h>

static PyObject *greeting(PyObject *self, PyObject *args) {
    (void)self;
    (void)args;
    return PyUnicode_FromString("Compiled Python version one");
}

static PyMethodDef methods[] = {
    {"greeting", greeting, METH_NOARGS, "Return the developer fixture greeting."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT, "cachy_extension", NULL, -1, methods,
    NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit_cachy_extension(void) {
    return PyModule_Create(&module);
}
