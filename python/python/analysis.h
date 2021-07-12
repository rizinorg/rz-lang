/* rizin - LGPL - Copyright 2017-2019 - pancake, xvilka, aronsky */

#ifndef _PY_ANALYSIS_H
#define _PY_ANALYSIS_H

#include <rz_analysis.h>
#include "common.h"

void py_export_analysis_enum(PyObject *tp_dict);

void Rizin_plugin_analysis_free(RzAnalysisPlugin *ap);

PyObject *Rizin_plugin_analysis(Rizin *self, PyObject *args);

#endif /* _PY_ANALYSIS_H */
