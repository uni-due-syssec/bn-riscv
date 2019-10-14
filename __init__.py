from .riscv import RISCV
from binaryninja import architecture, binaryview, enums

RISCV.register()

arch = architecture.Architecture['riscv']
binaryview.BinaryViewType['ELF'].register_arch(
    243, enums.Endianness.LittleEndian, arch
)