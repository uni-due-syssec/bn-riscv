from binaryninja import (Architecture, Endianness, RegisterInfo, SegmentFlag, InstructionInfo,
                         BinaryView, BranchType, InstructionTextToken, InstructionTextTokenType,
                         LowLevelILOperation, LowLevelILLabel, LLIL_TEMP, SectionSemantics)

from .const import ADDR_SIZE, INT_SIZE
from .instruction import decode
from capstone import *


def jump(il, addr, imm):
    dest = il.pop(ADDR_SIZE)
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(0), dest))
    il.append(il.jump(il.reg(ADDR_SIZE, LLIL_TEMP(addr))))
    return []


def j(il, addr, imm):
    dest = il.pop(ADDR_SIZE)
    il.append(il.set_reg(ADDR_SIZE, LLIL_TEMP(addr), dest))
    il.append(il.jump(il.reg(ADDR_SIZE, LLIL_TEMP(addr))))
    return []


def addi(il, addr, imm):
    dest = il.pop(ADDR_SIZE)
    return il.push(ADDR_SIZE, il.store(ADDR_SIZE, dest, il.add(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))))


def move(il, addr, imm):
    # il.append(
    #     il.store(
    #         ADDR_SIZE, il.reg(ADDR_SIZE, imm[:2]),#il.pop(ADDR_SIZE)),
    #         il.reg(ADDR_SIZE, imm[-2:])#il.pop(ADDR_SIZE))
    #     )
    # )
    il.append(
        il.set_reg(
            ADDR_SIZE, imm[:2],
            il.load(ADDR_SIZE, il.reg(ADDR_SIZE, imm[-2:]))
        )
    )
    return []


def nop(il, addr, imm):
    il.pop(ADDR_SIZE)
    return il.push(ADDR_SIZE, il.nop())


ins_il = {
    'ld': lambda il, addr, imm: il.push(
      ADDR_SIZE, il.store(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    ),
    'lui'
    'auipc'
    'j': lambda il, addr, imm: il.push(
        ADDR_SIZE, il.jump(il.pop(ADDR_SIZE))
    ),
    'jal': jump,
    'jalr'
    'beq': lambda il, addr, imm: il.push(
      ADDR_SIZE, il.compare_equal(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))  # jump
    ),
    'bne': lambda il, addr, imm: il.push(
      ADDR_SIZE, il.compare_not_equal(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))  # jump
    ),
    'blt': lambda il, addr, imm: il.push(
      ADDR_SIZE, il.compare_signed_less_than(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))  # jump
    ),
    'bge'
    'bltu'
    'bgeu'
    'li': lambda il, addr, imm: il.push(
      ADDR_SIZE, il.store(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    ),
    'lb': lambda il, addr, imm: il.push(
      0.5*ADDR_SIZE, il.sign_extend(ADDR_SIZE, il.pop(ADDR_SIZE))
    ),
    'lh': lambda il, addr, imm: il.push(
      ADDR_SIZE, il.sign_extend(ADDR_SIZE, il.pop(ADDR_SIZE))
    ),
    'lw'
    'lbu': lambda il, addr, imm: il.push(
      0.5*ADDR_SIZE, il.zero_extend(ADDR_SIZE, il.pop(ADDR_SIZE))
    ),
    'lhu': lambda il, addr, imm: il.push(
      ADDR_SIZE, il.zero_extend(ADDR_SIZE, il.pop(ADDR_SIZE))
    ),
    'sb'
    'sh'
    'sw': lambda il, addr, imm: il.push(
      ADDR_SIZE, il.store(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    ),
    'addi': addi,
    'slti'
    'sltiu'
    'xori'
    'ori'
    'andi'
    'slli'
    'srai': lambda il, addr, imm: il.push(
      ADDR_SIZE, il.arith_shift_right(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    ),
    'srli': lambda il, addr, imm: il.push(
      ADDR_SIZE, il.logical_shift_right(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    ),
    'add': lambda il, addr, imm: il.push(
      ADDR_SIZE, il.add(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    ),
    'sub': lambda il, addr, imm: il.push(
        ADDR_SIZE, il.sub(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    ),
    'sll'
    'slt': lambda il, addr, imm: il.push(
        ADDR_SIZE, il.compare_signed_less_than(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    ),
    'sltu': lambda il, addr, imm: il.push(
        ADDR_SIZE, il.compare_unsigned_less_than(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    ),
    'xor': lambda il, addr, imm: il.push(
        ADDR_SIZE, il.xor_expr(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    ),
    'srl'
    'sra'
    'or': lambda il, addr, imm: il.push(
        ADDR_SIZE, il.or_expr(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    ),
    'and': lambda il, addr, imm: il.push(
        ADDR_SIZE, il.and_expr(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    ),
    'ecall'
    'ebreak'
    'mul': lambda il, addr, imm: il.push(
        ADDR_SIZE, il.mult(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    ),
    'mulh'
    'mulhasu'
    'mulhu'
    'div': lambda il, addr, imm: il.push(
        ADDR_SIZE, il.div_signed(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    ),
    'divu': lambda il, addr, imm: il.push(
        ADDR_SIZE, il.div_unsigned(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    ),
    'rem': lambda il, addr, imm: il.push(
        ADDR_SIZE, il.mod_signed(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    ),
    'remu': lambda il, addr, imm: il.push(
        ADDR_SIZE, il.mod_unsigned(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    ),
    'mv': move,
    'nop': nop,
    'ret': lambda il, addr, imm: il.ret(il.pop(ADDR_SIZE)),
}


class RISCV(Architecture):
    name = "riscv"

    address_size = ADDR_SIZE
    default_int_size = INT_SIZE

    instr_alignment = 1
    max_instr_length = 33

    endianness = Endianness.LittleEndian

    regs = {
        "zero": RegisterInfo("zero", ADDR_SIZE),    # hard-wired zero
        "ra": RegisterInfo("ra", ADDR_SIZE),        # return address
        "sp": RegisterInfo("sp", ADDR_SIZE),        # stack pointer
        "gp": RegisterInfo("gp", ADDR_SIZE),        # global pointer
        "tp": RegisterInfo("tp", ADDR_SIZE),        # thread pointer
        "t0": RegisterInfo("t0", ADDR_SIZE),        # temporaries
        "t1": RegisterInfo("t1", ADDR_SIZE),
        "t2": RegisterInfo("t2", ADDR_SIZE),
        "s0": RegisterInfo("s0", ADDR_SIZE),        # saved register (frame pointer)
        "s1": RegisterInfo("s1", ADDR_SIZE),
        "a0": RegisterInfo("a0", ADDR_SIZE),        # return values
        "a1": RegisterInfo("a1", ADDR_SIZE),        # function arguments
        "a2": RegisterInfo("a2", ADDR_SIZE),
        "a3": RegisterInfo("a3", ADDR_SIZE),
        "a4": RegisterInfo("a4", ADDR_SIZE),
        "a5": RegisterInfo("a5", ADDR_SIZE),
        "a6": RegisterInfo("a6", ADDR_SIZE),
        "a7": RegisterInfo("a7", ADDR_SIZE),
        "s2": RegisterInfo("s2", ADDR_SIZE),        # saved registers
        "s3": RegisterInfo("s3", ADDR_SIZE),
        "s4": RegisterInfo("s4", ADDR_SIZE),
        "s5": RegisterInfo("s5", ADDR_SIZE),
        "s6": RegisterInfo("s6", ADDR_SIZE),
        "s7": RegisterInfo("s7", ADDR_SIZE),
        "s8": RegisterInfo("s8", ADDR_SIZE),
        "s9": RegisterInfo("s9", ADDR_SIZE),
        "s10": RegisterInfo("s10", ADDR_SIZE),
        "s11": RegisterInfo("s11", ADDR_SIZE),
        "t3": RegisterInfo("t3", ADDR_SIZE),        # temporaries
        "t4": RegisterInfo("t4", ADDR_SIZE),
        "t5": RegisterInfo("t5", ADDR_SIZE),
        "t6": RegisterInfo("t6", ADDR_SIZE),
    }

    stack_pointer = "sp"

    def get_instruction_info(self, data, addr):

        instr = decode(data, addr)

        result = InstructionInfo()
        result.length = instr.size

        if instr.name == 'ret':
            result.add_branch(BranchType.FunctionReturn)
        if instr.name in ['jal', 'j']:
            # JAL stores the address of the instruction following the jump (pc+4) into register rd
            result.add_branch(BranchType.UnconditionalBranch, addr + int(instr.operand, 16))

        return result

    def get_instruction_text(self, data, addr):

        instr = decode(data, addr)

        tokens = [InstructionTextToken(
            InstructionTextTokenType.TextToken,
            "{:7} ".format(
                instr.name
            )
        ), InstructionTextToken(
            InstructionTextTokenType.IntegerToken,
            instr.operand
        )]

        return tokens, instr.size

    # str data: max_instruction_length bytes from the binary at virtual address ``addr``
    # int addr: virtual address of bytes in ``data``
    # LowLevelILFunction il: The function the current instruction belongs to
    # int return: the length of the current instruction
    def get_instruction_low_level_il(self, data, addr, il):

        instr = decode(data, addr)

        il_func = ins_il.get(instr.name, None)

        if il_func is None:

            il.append(il.nop())

            return instr.size

        il_comp = il_func(il, addr, instr.operand)
        if isinstance(il_comp, list):
            for i in il_comp:
                il.append(i)
        else:
            il.append(il_comp)

        return instr.size


class RISCVView(BinaryView):
    name = "riscvView"
    long_name = "RiscV Bytecode"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.raw = data

    def init(self):
        self.arch = Architecture['riscv']
        self.platform = Architecture['riscv'].standalone_platform
        self.max_function_size_for_analysis = 0

        file_size = len(self.raw)

        self.add_auto_segment(
            0, file_size,
            0, file_size,
            (
                SegmentFlag.SegmentReadable |
                SegmentFlag.SegmentExecutable
            )
        )

        self.add_user_section("", 0, file_size, SectionSemantics.ReadOnlyCodeSectionSemantics)

        self.add_entry_point(0)

        return True

    @staticmethod
    def is_valid_for_data(data):
        return data.file.original_filename.endswith('.risc')
