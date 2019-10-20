from binaryninja import architecture, binaryview, enums
from .riscv import RISCV, RISCV64
from .calling_convention import DefaultCallingConvention

RISCV.register()
RISCV64.register()

arch = architecture.Architecture['riscv']
arch.register_calling_convention(DefaultCallingConvention(arch, 'default'))
arch.standalone_platform.default_calling_convention = arch.calling_conventions['default']
binaryview.BinaryViewType['ELF'].register_arch(
    243, enums.Endianness.LittleEndian, arch
)
