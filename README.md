# bn-riscv

An architecture plug-in that allows binary ninja to load RISC-V ELF binaries.

## Installation

First, you will need an installation of [capstone](https://github.com/aquynh/capstone) that supports RISC-V. Currently you have to install the `next` branch, e.g.,:

```
pip install --user 'git+https://github.com/aquynh/capstone.git@next#subdirectory=bindings/python'
```

The drop this into your plugins directory manually.
