/* rizin - LGPL - Copyright 2017-2019 - pancake, xvilka, aronsky */

#ifndef _PY_IO_H
#define _PY_IO_H

#include <rz_io.h>
#include "common.h"

void Rizin_plugin_io_free(RzIOPlugin *ap);

PyObject *Rizin_plugin_io(Rizin* self, PyObject *args);

#endif /* _PY_IO_H */
