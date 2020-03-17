# Copyright 2020 Katharina Utz <katharina.utz@stud.uni-due.de>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


from binaryninja import architecture, binaryview, enums
from .riscv import RISCV, RISCV64
from .calling_convention import RVGCallingConvention

RISCV.register()

_rvarch = architecture.Architecture['riscv']
_rvarch.register_calling_convention(RVGCallingConvention(_rvarch, 'default'))
_rvarch.standalone_platform.default_calling_convention = _rvarch.calling_conventions['default']
binaryview.BinaryViewType['ELF'].register_arch(
    243, enums.Endianness.LittleEndian, _rvarch
)

RISCV64.register()
_rvarch64 = architecture.Architecture['riscv64']
_rvarch64.register_calling_convention(RVGCallingConvention(_rvarch64, 'default'))
_rvarch64.standalone_platform.default_calling_convention = _rvarch64.calling_conventions['default']

# NOTE: currently there is only one ELF e_machine type for risc-v (243 or
# 0xf3). This is different to other architectures such as ARM or x86, where
# they have different e_machine types for 32/64 bit. As such the binary ninja
# API does not let us distinguish between risc-v 32/64 bit. 

# binaryview.BinaryViewType['ELF'].register_arch(
#     243, enums.Endianness.LittleEndian, _rvarch64
# )
