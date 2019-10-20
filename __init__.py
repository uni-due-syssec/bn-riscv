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

arch64 = architecture.Architecture['riscv64']
arch64.register_calling_convention(DefaultCallingConvention(arch64, 'default'))
arch64.standalone_platform.default_calling_convention = arch64.calling_conventions['default']
binaryview.BinaryViewType['ELF'].register_arch(
    243, enums.Endianness.LittleEndian, arch64
)

