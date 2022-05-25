# rizin-rlang

RzLang plugins are used to instantiate a VM inside rizin to run scripts by keeping the
internal state alive along multiple executions. This is like interpreting scripts using
rz-pipe, but with extra features:

* No need to instantiate and load the libraries on every call
* Keep global state between runs
* Write asm/analysis/bin plugins in dynamic languages
* Support Python

## Building

### Python

```sh
cd python
meson build
ninja -C build
ninja -C build install
```
