from binaryninja import (Architecture, Endianness, RegisterInfo, SegmentFlag, InstructionInfo,
                         BinaryView, BranchType, InstructionTextToken, InstructionTextTokenType,
                         LowLevelILOperation, LowLevelILLabel, LLIL_TEMP, SectionSemantics)

from .const import ADDR_SIZE, INT_SIZE
from .instruction import decode


def jal(il, op, imm):
    il.append(il.set_reg(ADDR_SIZE, 'ra',
                         il.add(ADDR_SIZE,
                                il.reg(ADDR_SIZE, 'sp'),
                                il.const(ADDR_SIZE, 4)
                                )
                         )
              )
    j(il, op, imm)


def j(il, op, imm):
    dest = il.add(ADDR_SIZE,
                  il.reg(ADDR_SIZE, 'sp'),
                  il.const(ADDR_SIZE, imm)
                  )
    il.append(il.jump(dest))


def beq(il, op, imm):
    cond = il.compare_equal(ADDR_SIZE,
                            il.reg(ADDR_SIZE, op[0]),
                            il.reg(ADDR_SIZE, op[1])
                            )
    condBranch(il, cond, imm)


def bne(il, op, imm):
    cond = il.compare_not_equal(ADDR_SIZE,
                                il.reg(ADDR_SIZE, op[0]),
                                il.reg(ADDR_SIZE, op[1])
                                )
    condBranch(il, cond, imm)


def condBranch(il, cond, imm):
    t = il.get_label_for_address(
        Architecture['riscv'],
        il.current_address + imm
    )
    if t is None:
        t = LowLevelILLabel()

    f_label_found = True

    f = il.get_label_for_address(
        Architecture['riscv'],
        il.current_address + 2
    )
    if f is None:
        f = LowLevelILLabel()
        f_label_found = False

    il.append(il.if_expr(cond, t, f))

    if not f_label_found:
        il.mark_label(f)


def add(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.add(ADDR_SIZE,
                          il.reg(ADDR_SIZE, op[1]),
                          il.reg(ADDR_SIZE, op[2])
                          )
                   )
    )


def addi(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.add(ADDR_SIZE,
                          il.reg(ADDR_SIZE, op[1]),
                          il.const(ADDR_SIZE, imm)
                          )
                   )
    )


def sub(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.sub(ADDR_SIZE,
                          il.reg(ADDR_SIZE, op[1]),
                          il.reg(ADDR_SIZE, op[2])
                          )
                   )
    )


def and_expr(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.and_expr(ADDR_SIZE,
                               il.reg(ADDR_SIZE, op[1]),
                               il.reg(ADDR_SIZE, op[2])
                               )
                   )
    )


def andi(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.and_expr(ADDR_SIZE,
                               il.reg(ADDR_SIZE, op[1]),
                               il.const(ADDR_SIZE, imm)
                               )
                   )
    )


def or_expr(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.or_expr(ADDR_SIZE,
                              il.reg(ADDR_SIZE, op[1]),
                              il.reg(ADDR_SIZE, op[2])
                              )
                   )
    )


def ori(il, op, imm):
    # op = operand.split()
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.or_expr(ADDR_SIZE,
                              il.reg(ADDR_SIZE, op[1]),
                              il.const(ADDR_SIZE, imm)
                              )
                   )
    )


def xor(il, op, imm):
    # op = operand.split()
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.xor_expr(ADDR_SIZE,
                               il.reg(ADDR_SIZE, op[1]),
                               il.reg(ADDR_SIZE, op[2])
                               )
                   )
    )


def xori(il, op, imm):
    # op = operand.split()
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.xor_expr(ADDR_SIZE,
                               il.reg(ADDR_SIZE, op[1]),
                               il.const(ADDR_SIZE, imm)
                               )
                   )
    )


def sll(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.shift_left(ADDR_SIZE,
                                 il.reg(ADDR_SIZE, op[1]),
                                 il.reg(ADDR_SIZE, op[2])
                                 )
                   )
    )


def slli(il, op, imm):
    # op = operand.split()
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.shift_left(ADDR_SIZE,
                                 il.reg(ADDR_SIZE, op[1]),
                                 il.const(ADDR_SIZE, imm)
                                 )
                   )
    )


def srl(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.logical_shift_right(ADDR_SIZE,
                                          il.reg(ADDR_SIZE, op[1]),
                                          il.reg(ADDR_SIZE, op[2])
                                          )
                   )
    )


def srli(il, op, imm):
    # op = operand.split()
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.logical_shift_right(ADDR_SIZE,
                                          il.reg(ADDR_SIZE, op[1]),
                                          il.const(ADDR_SIZE, imm)
                                          )
                   )
    )


def sra(il, op, imm):
    # op = operand.split()
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.arith_shift_right(ADDR_SIZE,
                                        il.reg(ADDR_SIZE, op[1]),
                                        il.reg(ADDR_SIZE, op[2])
                                        )
                   )
    )


def srai(il, op, imm):
    # op = operand.split()
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.arith_shift_right(ADDR_SIZE,
                                        il.reg(ADDR_SIZE, op[1]),
                                        il.const(ADDR_SIZE, imm)
                                        )
                   )
    )


def lui(il, op, imm):
    # op = operand.split()
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.zero_extend(ADDR_SIZE, il.const(ADDR_SIZE, imm))
                   )
    )


def auipc(il, op, imm):
    # op = operand.split()
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.add(ADDR_SIZE,
                          il.reg(ADDR_SIZE, 'pc'),
                          il.zero_extend(ADDR_SIZE, il.const(ADDR_SIZE, imm))
                          )
                   )
    )


def storeWord(il, op, imm):
    # op = operand.split()
    offset = il.add(ADDR_SIZE, il.reg(ADDR_SIZE, op[1]), il.const(ADDR_SIZE, imm))
    il.append(
        il.store(ADDR_SIZE, offset,
                 il.reg(ADDR_SIZE, op[0])
                 )
    )


def loadWord(il, op, imm):
    # op = operand.split()
    offset = il.add(ADDR_SIZE, il.reg(ADDR_SIZE, op[1]), il.const(ADDR_SIZE, imm))
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.load(ADDR_SIZE, offset)
                   )
    )


def move(il, op, imm):
    # op = operand.split()
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.reg(ADDR_SIZE, op[1])
                   )
    )


def slt(il, op, imm):
    # op = operand.split()
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.compare_signed_less_than(ADDR_SIZE,
                                               il.reg(ADDR_SIZE, op[1]),
                                               il.reg(ADDR_SIZE, op[2])
                                               )
                   )
    )


def sltu(il, op, imm):
    # op = operand.split()
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.compare_unsigned_less_than(ADDR_SIZE,
                                                 il.reg(ADDR_SIZE, op[1]),
                                                 il.reg(ADDR_SIZE, op[2])
                                                 )
                   )
    )


def slti(il, op, imm):
    # op = operand.split()
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.compare_signed_less_than(ADDR_SIZE,
                                               il.reg(ADDR_SIZE, op[1]),
                                               il.const(ADDR_SIZE, imm)
                                               )
                   )
    )


def sltiu(il, op, imm):
    # op = operand.split()
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.compare_unsigned_less_than(ADDR_SIZE,
                                               il.reg(ADDR_SIZE, op[1]),
                                               il.const(ADDR_SIZE, imm)
                                               )
                   )
    )


ins_il = {
    # 'ld': lambda il, addr, imm: il.push(
    #   ADDR_SIZE, il.store(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    # ),
    'lui': lui,
    'auipc': auipc,
    'j': j,
    'jal': jal,
    # 'jalr'
    'beq': beq,
    'bne': bne,
    # 'blt': lambda il, addr, imm: il.push(
    #   ADDR_SIZE, il.compare_signed_less_than(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))  # jump
    # ),
    # 'bge'
    # 'bltu'
    # 'bgeu'
    # 'li': lambda il, addr, imm: il.push(
    #   ADDR_SIZE, il.store(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    # ),
    # 'lb': lambda il, addr, imm: il.push(
    #   0.5*ADDR_SIZE, il.sign_extend(ADDR_SIZE, il.pop(ADDR_SIZE))
    # ),
    # 'lh': lambda il, addr, imm: il.push(
    #   ADDR_SIZE, il.sign_extend(ADDR_SIZE, il.pop(ADDR_SIZE))
    # ),
    'lw': loadWord,
    # 'lbu': lambda il, addr, imm: il.push(
    #   0.5*ADDR_SIZE, il.zero_extend(ADDR_SIZE, il.pop(ADDR_SIZE))
    # ),
    # 'lhu': lambda il, addr, imm: il.push(
    #   ADDR_SIZE, il.zero_extend(ADDR_SIZE, il.pop(ADDR_SIZE))
    # ),
    # 'sb'
    # 'sh'
    'sw': storeWord,
    'addi': addi,
    'slti': slti,
    'sltiu': sltiu,
    'xori': xori,
    'ori': ori,
    'andi': andi,
    'slli': slli,
    'srai': srai,
    'srli': srli,
    'add': add,
    'sub': sub,
    'sll': sll,
    # 'slt': lambda il, addr, imm: il.push(
    #     ADDR_SIZE, il.compare_signed_less_than(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    # ),
    'sltu': sltu,
    'xor': xor,
    'srl': srl,
    'sra': sra,
    'or': or_expr,
    'and': and_expr,
    # 'ecall'
    # 'ebreak'
    # 'mul': lambda il, addr, imm: il.push(
    #     ADDR_SIZE, il.mult(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    # ),
    # 'mulh'
    # 'mulhasu'
    # 'mulhu'
    # 'div': lambda il, addr, imm: il.push(
    #     ADDR_SIZE, il.div_signed(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    # ),
    # 'divu': lambda il, addr, imm: il.push(
    #     ADDR_SIZE, il.div_unsigned(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    # ),
    # 'rem': lambda il, addr, imm: il.push(
    #     ADDR_SIZE, il.mod_signed(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    # ),
    # 'remu': lambda il, addr, imm: il.push(
    #     ADDR_SIZE, il.mod_unsigned(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    # ),
    'mv': move,
    'nop': lambda il, op, imm: il.append(
      il.nop()
    ),
    # 'ret':        JALR x0, x1, 0  # return from subroutine
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
        "pc": RegisterInfo("pc", ADDR_SIZE),
    }

    stack_pointer = "sp"

    def get_instruction_info(self, data, addr):

        instr = decode(data, addr)

        result = InstructionInfo()
        result.length = 0

        if instr is not None:
            result.length = instr.size

            if instr.name == 'ret':
                result.add_branch(BranchType.FunctionReturn)
            elif instr.name in ['jal', 'j']:
                # JAL stores the address of the instruction following the jump (pc+4) into register rd
                result.add_branch(BranchType.UnconditionalBranch, addr + instr.imm)
            elif instr.name in ['beq', 'bne']:
                result.add_branch(BranchType.TrueBranch, addr + instr.imm)
                result.add_branch(BranchType.FalseBranch, addr + 4)

        return result

    def get_instruction_text(self, data, addr):

        instr = decode(data, addr)

        tokens = [InstructionTextToken(
            InstructionTextTokenType.TextToken,
            "{:6} ".format(
                instr.name
            )
        ), InstructionTextToken(
            InstructionTextTokenType.TextToken,
            "{:9}".format(
                instr.op
            )
        ), InstructionTextToken(
            InstructionTextTokenType.TextToken,
            " " + str(instr.imm)
        )]

        return tokens, instr.size

    # str data: max_instruction_length bytes from the binary at virtual address ``addr``
    # int addr: virtual address of bytes in ``data``
    # LowLevelILFunction il: The function the current instruction belongs to
    # int return: the length of the current instruction
    def get_instruction_low_level_il(self, data, addr, il):

        instr = decode(data, addr)

        if instr is not None:
            il_func = ins_il.get(instr.name)

            if il_func is None:
                il.append(il.unimplemented())

                return instr.size

            il_func(il, instr.op.split(), instr.imm)

            return instr.size

        return None


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
