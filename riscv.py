from binaryninja import (Architecture, Endianness, RegisterInfo, InstructionInfo,
                         BranchType, InstructionTextToken, InstructionTextTokenType,
                         LowLevelILLabel)

from binaryninja.enums import (LowLevelILOperation)

from .const import ADDR_SIZE, INT_SIZE
from .instruction import decode, gen_token


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


def jr(il, op, imm):
    if len(op) < 2:
        if len(op) < 1:
            dest = 'ra'
            base = 'zero'
        else:
            base = op[0]
            dest = 'ra'
    else:
        dest = op[0]
        base = op[1]

    il.append(
        il.jump(
            il.add(ADDR_SIZE,
                   il.reg(ADDR_SIZE, 'sp'),
                   il.const(ADDR_SIZE, imm)
                   )
            )
        )


def jalr(il, op, imm):
    if len(op) < 2:
        if len(op) < 1:
            dest = 'ra'
            base = 'zero'
        else:
            base = op[0]
            dest = 'ra'
    else:
        dest = op[0]
        base = op[1]

    il.append(il.set_reg(ADDR_SIZE, base,
                         il.and_expr(ADDR_SIZE,
                                     il.add(ADDR_SIZE,
                                            il.reg(ADDR_SIZE, base),
                                            il.const(12, imm)
                                            ),
                                     il.neg_expr(ADDR_SIZE, il.const(ADDR_SIZE, 2))
                                     )
                         )
              )
    il.append(il.set_reg(ADDR_SIZE, dest,
                         il.add(ADDR_SIZE,
                                il.reg(ADDR_SIZE, 'sp'),
                                il.const(ADDR_SIZE, 4))
                         )
              )


def beq(il, op, imm):
    cond = il.compare_equal(ADDR_SIZE,
                            il.reg(ADDR_SIZE, op[0]),
                            il.reg(ADDR_SIZE, op[1])
                            )
    condBranch(il, cond, imm)


def beqz(il, op, imm):
    cond = il.compare_equal(ADDR_SIZE,
                            il.reg(ADDR_SIZE, op[0]),
                            il.const(ADDR_SIZE, 0)
                            )
    condBranch(il, cond, imm)


def bne(il, op, imm):
    cond = il.compare_not_equal(ADDR_SIZE,
                                il.reg(ADDR_SIZE, op[0]),
                                il.reg(ADDR_SIZE, op[1])
                                )
    condBranch(il, cond, imm)


def bnez(il, op, imm):
    cond = il.compare_not_equal(ADDR_SIZE,
                                il.reg(ADDR_SIZE, op[0]),
                                il.const(ADDR_SIZE, 0)
                                )
    condBranch(il, cond, imm)


def blt(il, op, imm):
    cond = il.compare_signed_less_than(ADDR_SIZE,
                                       il.reg(ADDR_SIZE, op[0]),
                                       il.reg(ADDR_SIZE, op[1])
                                       )
    condBranch(il, cond, imm)


def bltu(il, op, imm):
    cond = il.compare_unsigned_less_than(ADDR_SIZE,
                                         il.reg(ADDR_SIZE, op[0]),
                                         il.reg(ADDR_SIZE, op[1])
                                         )
    condBranch(il, cond, imm)


def bltz(il, op, imm):
    cond = il.compare_signed_less_than(ADDR_SIZE,
                                       il.reg(ADDR_SIZE, op[0]),
                                       il.const(ADDR_SIZE, 0)
                                       )
    condBranch(il, cond, imm)


def bgtz(il, op, imm):
    cond = il.compare_signed_less_than(ADDR_SIZE,
                                       il.const(ADDR_SIZE, 0),
                                       il.reg(ADDR_SIZE, op[0])
                                       )
    condBranch(il, cond, imm)


def bge(il, op, imm):
    cond = il.compare_signed_greater_equal(ADDR_SIZE,
                                           il.reg(ADDR_SIZE, op[0]),
                                           il.reg(ADDR_SIZE, op[1])
                                           )
    condBranch(il, cond, imm)


def bgeu(il, op, imm):
    cond = il.compare_unsigned_greater_equal(ADDR_SIZE,
                                             il.reg(ADDR_SIZE, op[0]),
                                             il.reg(ADDR_SIZE, op[0])
                                             )
    condBranch(il, cond, imm)


def blez(il, op, imm):
    cond = il.compare_signed_greater_equal(ADDR_SIZE,
                                           il.const(ADDR_SIZE, 0),
                                           il.reg(ADDR_SIZE, op[0])
                                           )
    condBranch(il, cond, imm)


def bgez(il, op, imm):
    cond = il.compare_unsigned_greater_equal(ADDR_SIZE,
                                             il.reg(ADDR_SIZE, op[0]),
                                             il.const(ADDR_SIZE, 0)
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
        il.current_address + 4
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


def neg(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.neg_expr(ADDR_SIZE,
                               il.reg(ADDR_SIZE, op[1])
                               )
                   )
    )


def not_expr(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.not_expr(ADDR_SIZE,
                               il.reg(ADDR_SIZE, op[1])))
    )


def mult(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.mult(ADDR_SIZE,
                           il.reg(ADDR_SIZE, op[1]),
                           il.reg(ADDR_SIZE, op[2])
                           )
                   )
    )


def div(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.div_signed(ADDR_SIZE,
                                 il.reg(ADDR_SIZE, op[1]),
                                 il.reg(ADDR_SIZE, op[2])
                                 )
                   )
    )


def divu(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.div_unsigned(ADDR_SIZE,
                                   il.reg(ADDR_SIZE, op[1]),
                                   il.reg(ADDR_SIZE, op[2])
                                   )
                   )
    )


def mod(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.mod_signed(ADDR_SIZE,
                                 il.reg(ADDR_SIZE, op[1]),
                                 il.reg(ADDR_SIZE, op[2])
                                 )
                   )
    )


def modu(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.mod_unsigned(ADDR_SIZE,
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
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.or_expr(ADDR_SIZE,
                              il.reg(ADDR_SIZE, op[1]),
                              il.const(ADDR_SIZE, imm)
                              )
                   )
    )


def xor(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.xor_expr(ADDR_SIZE,
                               il.reg(ADDR_SIZE, op[1]),
                               il.reg(ADDR_SIZE, op[2])
                               )
                   )
    )


def xori(il, op, imm):
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
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.logical_shift_right(ADDR_SIZE,
                                          il.reg(ADDR_SIZE, op[1]),
                                          il.const(ADDR_SIZE, imm)
                                          )
                   )
    )


def sra(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.arith_shift_right(ADDR_SIZE,
                                        il.reg(ADDR_SIZE, op[1]),
                                        il.reg(ADDR_SIZE, op[2])
                                        )
                   )
    )


def srai(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.arith_shift_right(ADDR_SIZE,
                                        il.reg(ADDR_SIZE, op[1]),
                                        il.const(ADDR_SIZE, imm)
                                        )
                   )
    )


def lui(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.zero_extend(ADDR_SIZE, il.const(3, imm))
                   )
    )


def auipc(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.add(ADDR_SIZE,
                          il.reg(ADDR_SIZE, 'pc'),
                          il.zero_extend(ADDR_SIZE, il.const(3, imm))
                          )
                   )
    )


def storeWord(il, op, imm):
    offset = il.add(ADDR_SIZE, il.reg(ADDR_SIZE, op[1]), il.const(ADDR_SIZE, imm))
    il.append(
        il.store(ADDR_SIZE, offset,
                 il.reg(ADDR_SIZE, op[0])
                 )
    )


def storeHalf(il, op, imm):
    offset = il.add(ADDR_SIZE, il.reg(ADDR_SIZE, op[1]), il.const(2, imm))
    il.append(
        il.store(ADDR_SIZE, offset,
                 il.reg(ADDR_SIZE, op[0])
                 )
    )


def storeByte(il, op, imm):
    offset = il.add(ADDR_SIZE, il.reg(ADDR_SIZE, op[1]), il.const(1, imm))
    il.append(
        il.store(ADDR_SIZE, offset,
                 il.reg(ADDR_SIZE, op[0])
                 )
    )


def loadByte(il, op, imm):
    offset = il.add(ADDR_SIZE, il.reg(ADDR_SIZE, op[1]), il.sign_extend(2, il.const(1, imm)))
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.load(1, offset)
                   )
    )


def loadByteZero(il, op, imm):
    offset = il.add(ADDR_SIZE, il.reg(ADDR_SIZE, op[1]), il.sign_extend(2, il.const(1, imm)))
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.zero_extend(ADDR_SIZE, il.load(1, offset))
                   )
    )


def loadHalf(il, op, imm):
    offset = il.add(ADDR_SIZE, il.reg(ADDR_SIZE, op[1]), il.sign_extend(2, il.const(2, imm)))
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.load(2, offset)
                   )
    )


def loadHalfZero(il, op, imm):
    offset = il.add(ADDR_SIZE, il.reg(ADDR_SIZE, op[1]), il.zero_extend(22, il.const(2, imm)))
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.zero_extend(ADDR_SIZE, il.load(16, offset))
                   )
    )


def loadWord(il, op, imm):
    offset = il.add(ADDR_SIZE, il.reg(ADDR_SIZE, op[1]), il.const(ADDR_SIZE, imm))
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.load(ADDR_SIZE, offset)
                   )
    )


def move(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.reg(ADDR_SIZE, op[1])
                   )
    )


def slt(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.compare_signed_less_than(ADDR_SIZE,
                                               il.reg(ADDR_SIZE, op[1]),
                                               il.reg(ADDR_SIZE, op[2])
                                               )
                   )
    )


def sltu(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.compare_unsigned_less_than(ADDR_SIZE,
                                                 il.reg(ADDR_SIZE, op[1]),
                                                 il.reg(ADDR_SIZE, op[2])
                                                 )
                   )
    )


def slti(il, op, imm):
    il.append(
        il.set_reg(ADDR_SIZE, op[0],
                   il.compare_signed_less_than(ADDR_SIZE,
                                               il.reg(ADDR_SIZE, op[1]),
                                               il.const(ADDR_SIZE, imm)
                                               )
                   )
    )


def sltiu(il, op, imm):
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
    'jr': jr,
    'jal': jal,
    'jalr': jalr,
    'beq': beq,
    'beqz': beqz,
    'bne': bne,
    'bnez': bnez,
    'bge': bge,
    'bgeu': bgeu,
    'blez': blez,
    'bgez': bgez,
    'blt': blt,
    'bltu': bltu,
    'bltz': bltz,
    'bgtz': bgtz,
    # 'li': lambda il, addr, imm: il.push(
    #   ADDR_SIZE, il.store(ADDR_SIZE, il.pop(ADDR_SIZE), il.pop(ADDR_SIZE))
    # ),
    'lb': loadByte,
    'lh': loadHalf,
    'lw': loadWord,
    'lbu': loadByteZero,
    'lhu': loadHalfZero,
    'sb': storeByte,
    'sh': storeHalf,
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
    'neg': neg,
    'not': not_expr,
    'sll': sll,
    'slt': slt,
    'sltu': sltu,
    'xor': xor,
    'srl': srl,
    'sra': sra,
    'or': or_expr,
    'and': and_expr,
    'ecall': lambda il, op, imm: il.append(il.system_call()),
    # 'ebreak'
    'mul': mult,
    # 'mulh'
    # 'mulhasu'
    # 'mulhu'
    'div': div,
    'divu': divu,
    'rem': mod,
    'remu': modu,
    'mv': move,
    'nop': lambda il, op, imm: il.append(il.nop()),
    'ret': lambda il, op, imm: il.append(il.ret(il.const(ADDR_SIZE, imm)))  # return from subroutine
}

branch_ins = [
    'beq', 'bne', 'beqz', 'bnez', 'bge', 'bgeu',
    'blt', 'bltu', 'blez', 'bgez', 'bltz', 'bgtz'
]


class RISCV(Architecture):
    name = "riscv"

    address_size = 4
    default_int_size = 4

    # instr_alignment = 1
    max_instr_length = 4

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

        if instr is None:
            return None

        result = InstructionInfo()
        result.length = instr.size

        if instr.name == 'ret':
            result.add_branch(BranchType.FunctionReturn)
        elif instr.name in ['jal', 'jalr', 'j', 'jr']:
            result.add_branch(BranchType.UnconditionalBranch, addr + instr.imm)
        elif instr.name in branch_ins:
            result.add_branch(BranchType.TrueBranch, addr + instr.imm)
            result.add_branch(BranchType.FalseBranch, addr + 4)

        return result

    def get_instruction_text(self, data, addr):

        instr = decode(data, addr)

        if instr is None:
            return None

        tokens = gen_token(instr)

        return tokens, instr.size

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
