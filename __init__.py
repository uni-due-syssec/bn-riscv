from .riscv import RISCV, RISCVView
from binaryninja import architecture, binaryview, enums

RISCV.register()
RISCVView.register()

arch = architecture.Architecture['riscv']
binaryview.BinaryViewType['ELF'].register_arch(
    243, enums.Endianness.LittleEndian, arch
)