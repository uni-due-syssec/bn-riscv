from binaryninja import architecture, binaryview, enums
from .riscv import RISCV
from .const import DefaultCallingConvention

RISCV.register()

arch = architecture.Architecture['riscv']
arch.register_calling_convention(DefaultCallingConvention(arch, 'default'))
arch.standalone_platform.default_calling_convention = arch.calling_conventions['default']
binaryview.BinaryViewType['ELF'].register_arch(
    243, enums.Endianness.LittleEndian, arch
)
