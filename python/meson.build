project('rz-lang-python', 'c',
  version: '0.1.0',
  license: 'LGPL3',
  meson_version: '>=0.55.0',
  default_options: [
    'buildtype=debugoptimized',
    'b_vscrt=from_buildtype',
  ]
)

rz_core_dep = dependency('rz_core')
plugins_dir = get_option('prefix') / rz_core_dep.get_variable(pkgconfig: 'plugindir', cmake: 'rz_core_PLUGINDIR')
message('Plugins install directory: ' + plugins_dir)

python3_dep = dependency('python3-embed')

library('rz-lang-python',
  [
    'python.c',
    'python/asm.c',
    'python/analysis.c',
    'python/bin.c',
    'python/common.c',
    'python/io.c'
  ],
  dependencies: [rz_core_dep, python3_dep],
  install: true,
  install_dir: plugins_dir,
)
