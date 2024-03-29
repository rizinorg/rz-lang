// SPDX-FileCopyrightText: 2017-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2017-2019 aronsky <aronsky@gmail.com>
// SPDX-FileCopyrightText: 2017-2019 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _PY_COMMON_H
#define _PY_COMMON_H
#include <rz_lib.h>
#include <rz_lang.h>

#undef HAVE_SIGACTION

#undef _GNU_SOURCE
#undef _XOPEN_SOURCE
#undef _POSIX_C_SOURCE
#undef PREFIX

#include <Python.h>
#include <structmember.h>

#if PY_MAJOR_VERSION < 3
#error Python 2 support is deprecated, use Python 3 instead
#endif

typedef struct {
	PyObject_HEAD
		PyObject *first; /* first name */
	PyObject *last; /* last name */
	int number;
} Rizin;

PyObject *getO(PyObject *o, const char *name);

char *getS(PyObject *o, const char *name);

st64 getI(PyObject *o, const char *name);

void *getF(PyObject *o, const char *name);

bool getB(PyObject *o, const char *name);

#endif /* _PY_COMMON_H */
