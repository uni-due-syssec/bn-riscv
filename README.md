# bn-riscv

An architecture plug-in that allows binary ninja to load RISC-V ELF binaries.

## Installation

First, you will need an installation of [capstone](https://github.com/aquynh/capstone) that supports RISC-V. Currently you have to install the `next` branch, e.g.,:

```
pip install --user 'git+https://github.com/aquynh/capstone.git@next#subdirectory=bindings/python'
```

Then drop this repository into your plugins directory manually. Note that you should use it from master if possible, releases are somewhat rare.
