rizin-rlang
=============

RzLang plugins are used to instantiate a VM inside rizin to run scripts by keeping the
internal state alive along multiple executions. This is like interpreting scripts using
rz-pipe, but with extra features:

* No need to instantiate and load the libraries on every call
* Keep global state between runs
* Write asm/analysus/bin plugins in dynamic languages
* Support Python

Building
========

Check for dependencies and build

```sh
./configure --prefix=/usr
make
make install
```

If you want to build a specific plugin, just cd into the right directory.

```sh
./configure --prefix=/usr
cd python
make
make install
```
