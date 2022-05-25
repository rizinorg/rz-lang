// SPDX-FileCopyrightText: 2017-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2017-2019 aronsky <aronsky@gmail.com>
// SPDX-FileCopyrightText: 2017-2019 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _PY_IO_H
#define _PY_IO_H

#include <rz_io.h>
#include "common.h"

void Rizin_plugin_io_free(RzIOPlugin *ap);

PyObject *Rizin_plugin_io(Rizin *self, PyObject *args);

#endif /* _PY_IO_H */
