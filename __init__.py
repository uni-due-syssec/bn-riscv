from binaryninja import architecture, binaryview, enums
from .riscv import RISCV, RISCV64
from .calling_convention import DefaultCallingConvention

RISCV.register()

arch = architecture.Architecture['riscv']
arch.register_calling_convention(DefaultCallingConvention(arch, 'default'))
arch.standalone_platform.default_calling_convention = arch.calling_conventions['default']
binaryview.BinaryViewType['ELF'].register_arch(
    243, enums.Endianness.LittleEndian, arch
)


RISCV64.register()
_arch64 = architecture.Architecture['riscv64']
_arch64.register_calling_convention(DefaultCallingConvention(_arch64, 'default'))
_arch64.standalone_platform.default_calling_convention = _arch64.calling_conventions['default']

# NOTE: currently there is only one ELF e_machine type for risc-v (243 or
# 0xf3). This is different to other architectures such as ARM or x86, where
# they have different e_machine types for 32/64 bit. As such the binary ninja
# API does not let us distinguish between risc-v 32/64 bit. 

# binaryview.BinaryViewType['ELF'].register__arch64(
#     243, enums.Endianness.LittleEndian, _arch64
# )
