from binaryninja import (Architecture, LowLevelILLabel)

addr_size = 4
_arch_name = 'riscv'

class Lifter:

    def __init__(self, addr_size_, arch_name='riscv'):
        self.arch_name = arch_name
        global _arch_name
        _arch_name = arch_name

        global addr_size
        addr_size = addr_size_
        self.addr_size = addr_size_

        # TODO: remove the @staticmethod and use self.addr_size instead
        # TODO: make sure all expressions are lifted correctly for risc-v 64-bit

    @classmethod
    def lift(cls, il, instr, mnemonic):

        if mnemonic == 'or':
            mnemonic = 'or_expr'
        elif mnemonic == 'and':
            mnemonic = 'and_expr'
        elif mnemonic == 'not':
            mnemonic = 'not_expr'

        if hasattr(cls, mnemonic):
            getattr(cls, mnemonic)(il, instr.op.split(), instr.imm)
        else:
            il.append(il.unimplemented())

    @staticmethod
    def jal(il, op, imm):

        if len(op) < 1:
            ret_adr = 'ra'
        else:
            ret_adr = op[0]

        label = il.get_label_for_address(
            Architecture[_arch_name],
            il.current_address + imm
        )

        if ret_adr != 'zero':
            il.append(il.set_reg(addr_size, ret_adr, il.const(addr_size, il.current_address + 4)))

        if label is not None:
            il.append(il.goto(label))
        else:
            il.append(il.call(il.const(addr_size, il.current_address + imm)))


    @staticmethod
    def j(il, op, imm):
        op = ['zero']
        Lifter.jal(il, op, imm)

    @staticmethod
    def jr(il, op, imm):
        regs = ['zero', op[0]]
        Lifter.jalr(il, regs, imm)

    @staticmethod
    def jalr(il, op, imm):

        if len(op) < 2:
            ret_adr = 'ra'
            base = op[0]
        else:
            ret_adr = op[0]
            base = op[1]

        target = il.and_expr(addr_size,
                             il.add(addr_size,
                                    il.reg(addr_size, base),
                                    il.const(addr_size, imm)
                                    ),
                             il.neg_expr(addr_size, il.const(addr_size, 2))
                             )

        if ret_adr != 'zero':
            il.append(il.set_reg(addr_size, ret_adr, il.const(addr_size, il.current_address + 4)))

        il.append(il.call(target))


    @staticmethod
    def ret(il, op, imm):
        il.append(il.ret(il.and_expr(addr_size,
                                     il.reg(addr_size, 'ra'),
                                     il.neg_expr(addr_size, il.const(addr_size, 2))
                                     )
                         )
                  )
        il.append(il.pop(addr_size))

    @staticmethod
    def beq(il, op, imm):
        cond = il.compare_equal(addr_size,
                                il.reg(addr_size, op[0]),
                                il.reg(addr_size, op[1])
                                )
        Lifter.condBranch(il, cond, imm)

    @staticmethod
    def beqz(il, op, imm):
        cond = il.compare_equal(addr_size,
                                il.reg(addr_size, op[0]),
                                il.const(addr_size, 0)
                                )
        Lifter.condBranch(il, cond, imm)

    @staticmethod
    def bne(il, op, imm):
        cond = il.compare_not_equal(addr_size,
                                    il.reg(addr_size, op[0]),
                                    il.reg(addr_size, op[1])
                                    )
        Lifter.condBranch(il, cond, imm)

    @staticmethod
    def bnez(il, op, imm):
        cond = il.compare_not_equal(addr_size,
                                    il.reg(addr_size, op[0]),
                                    il.const(addr_size, 0)
                                    )
        Lifter.condBranch(il, cond, imm)

    @staticmethod
    def blt(il, op, imm):
        cond = il.compare_signed_less_than(addr_size,
                                           il.reg(addr_size, op[0]),
                                           il.reg(addr_size, op[1])
                                           )
        Lifter.condBranch(il, cond, imm)

    @staticmethod
    def bltu(il, op, imm):
        cond = il.compare_unsigned_less_than(addr_size,
                                             il.reg(addr_size, op[0]),
                                             il.reg(addr_size, op[1])
                                             )
        Lifter.condBranch(il, cond, imm)

    @staticmethod
    def bltz(il, op, imm):
        cond = il.compare_signed_less_than(addr_size,
                                           il.reg(addr_size, op[0]),
                                           il.const(addr_size, 0)
                                           )
        Lifter.condBranch(il, cond, imm)

    @staticmethod
    def bgtz(il, op, imm):
        cond = il.compare_signed_less_than(addr_size,
                                           il.const(addr_size, 0),
                                           il.reg(addr_size, op[0])
                                           )
        Lifter.condBranch(il, cond, imm)

    @staticmethod
    def bge(il, op, imm):
        cond = il.compare_signed_greater_equal(addr_size,
                                               il.reg(addr_size, op[0]),
                                               il.reg(addr_size, op[1])
                                               )
        Lifter.condBranch(il, cond, imm)

    @staticmethod
    def bgeu(il, op, imm):
        cond = il.compare_unsigned_greater_equal(addr_size,
                                                 il.reg(addr_size, op[0]),
                                                 il.reg(addr_size, op[0])
                                                 )
        Lifter.condBranch(il, cond, imm)

    @staticmethod
    def blez(il, op, imm):
        cond = il.compare_signed_greater_equal(addr_size,
                                               il.const(addr_size, 0),
                                               il.reg(addr_size, op[0])
                                               )
        Lifter.condBranch(il, cond, imm)

    @staticmethod
    def bgez(il, op, imm):
        cond = il.compare_unsigned_greater_equal(addr_size,
                                                 il.reg(addr_size, op[0]),
                                                 il.const(addr_size, 0)
                                                 )
        Lifter.condBranch(il, cond, imm)

    @staticmethod
    def condBranch(il, cond, imm):
        dest = il.add(addr_size,
                      il.const(addr_size, il.current_address),
                      il.sign_extend(addr_size,
                                     il.const(addr_size, imm)
                                     )
                      )

        t = il.get_label_for_address(
            Architecture['riscv'],
            il.current_address + imm
        )
        if t is None:
            t = LowLevelILLabel()
            indirect = True
        else:
            indirect = False

        f_label_found = True

        f = il.get_label_for_address(
            Architecture['riscv'],
            il.current_address + 4
        )
        if f is None:
            f = LowLevelILLabel()
            f_label_found = False

        il.append(il.if_expr(cond, t, f))

        if indirect:
            il.mark_label(t)
            il.append(il.jump(dest))

        if not f_label_found:
            il.mark_label(f)

    @staticmethod
    def add(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.add(addr_size,
                              il.reg(addr_size, op[1]),
                              il.reg(addr_size, op[2])
                              )
                       )
        )

    @staticmethod
    def addi(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.add(addr_size,
                              il.reg(addr_size, op[1]),
                              il.const(addr_size, imm)
                              )
                       )
        )

    @staticmethod
    def sub(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.sub(addr_size,
                              il.reg(addr_size, op[1]),
                              il.reg(addr_size, op[2])
                              )
                       )
        )

    @staticmethod
    def neg(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.neg_expr(addr_size,
                                   il.reg(addr_size, op[1])
                                   )
                       )
        )

    @staticmethod
    def not_expr(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.not_expr(addr_size,
                                   il.reg(addr_size, op[1])))
        )

    @staticmethod
    def mul(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.mult(addr_size,
                               il.reg(addr_size, op[1]),
                               il.reg(addr_size, op[2])
                               )
                       )
        )

    @staticmethod
    def div(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.div_signed(addr_size,
                                     il.reg(addr_size, op[1]),
                                     il.reg(addr_size, op[2])
                                     )
                       )
        )

    @staticmethod
    def divu(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.div_unsigned(addr_size,
                                       il.reg(addr_size, op[1]),
                                       il.reg(addr_size, op[2])
                                       )
                       )
        )

    @staticmethod
    def mod(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.mod_signed(addr_size,
                                     il.reg(addr_size, op[1]),
                                     il.reg(addr_size, op[2])
                                     )
                       )
        )

    @staticmethod
    def modu(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.mod_unsigned(addr_size,
                                       il.reg(addr_size, op[1]),
                                       il.reg(addr_size, op[2])
                                       )
                       )
        )

    @staticmethod
    def and_expr(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.and_expr(addr_size,
                                   il.reg(addr_size, op[1]),
                                   il.reg(addr_size, op[2])
                                   )
                       )
        )

    @staticmethod
    def andi(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.and_expr(addr_size,
                                   il.reg(addr_size, op[1]),
                                   il.sign_extend(addr_size,
                                                  il.and_expr(2,
                                                              il.const(2, imm),
                                                              il.const(2, 0xfff)
                                                              )
                                                  )
                                   )
                       )
        )

    @staticmethod
    def or_expr(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.or_expr(addr_size,
                                  il.reg(addr_size, op[1]),
                                  il.reg(addr_size, op[2])
                                  )
                       )
        )

    @staticmethod
    def ori(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.or_expr(addr_size,
                                  il.reg(addr_size, op[1]),
                                  il.sign_extend(addr_size,
                                                 il.and_expr(2,
                                                             il.const(2, imm),
                                                             il.const(2, 0xfff)
                                                             )
                                                 )
                                  )
                       )
        )

    @staticmethod
    def xor(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.xor_expr(addr_size,
                                   il.reg(addr_size, op[1]),
                                   il.reg(addr_size, op[2])
                                   )
                       )
        )

    @staticmethod
    def xori(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.xor_expr(addr_size,
                                   il.reg(addr_size, op[1]),
                                   il.sign_extend(addr_size,
                                                  il.and_expr(2,
                                                              il.const(2, imm),
                                                              il.const(2, 0xfff)
                                                              )
                                                  )
                                   )
                       )
        )

    @staticmethod
    def sll(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.shift_left(addr_size,
                                     il.reg(addr_size, op[1]),
                                     il.reg(addr_size, op[2])
                                     )
                       )
        )

    @staticmethod
    def slli(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.shift_left(addr_size,
                                     il.reg(addr_size, op[1]),
                                     il.and_expr(1,
                                                 il.const(1, imm),
                                                 il.const(1, 0xf)
                                                 )
                                     )
                       )
        )

    @staticmethod
    def srl(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.logical_shift_right(addr_size,
                                              il.reg(addr_size, op[1]),
                                              il.reg(addr_size, op[2])
                                              )
                       )
        )

    @staticmethod
    def srli(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.logical_shift_right(addr_size,
                                              il.reg(addr_size, op[1]),
                                              il.and_expr(1,
                                                          il.const(1, imm),
                                                          il.const(1, 0xf)
                                                          )
                                              )
                       )
        )

    @staticmethod
    def sra(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.arith_shift_right(addr_size,
                                            il.reg(addr_size, op[1]),
                                            il.reg(addr_size, op[2])
                                            )
                       )
        )

    @staticmethod
    def srai(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.arith_shift_right(addr_size,
                                            il.reg(addr_size, op[1]),
                                            il.const(addr_size, imm)
                                            )
                       )
        )

    @staticmethod
    def lui(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       # il.shift_left(addr_size, 
                       #               il.zero_extend(addr_size, il.const(3, imm)),
                       #               # il.const(addr_size, imm)),
                       #               il.const(addr_size, 12))
                       il.const(addr_size, imm << 12)
                       )
        )

    @staticmethod
    def auipc(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.add(addr_size,
                              il.reg(addr_size, 'pc'),
                              il.zero_extend(addr_size,
                                             il.and_expr(3,
                                                         il.const(3, imm),
                                                         il.const(3, 0xfffff)
                                                         )
                                             )
                              )
                       )
        )

    @staticmethod
    def sw(il, op, imm):
        offset = il.add(addr_size,
                        il.reg(addr_size, op[1]),
                        il.const(addr_size, imm)
                        )
        il.append(
            il.store(addr_size, offset,
                     il.reg(addr_size, op[0])
                     )
        )

    @staticmethod
    def sh(il, op, imm):
        offset = il.add(addr_size,
                        il.reg(addr_size, op[1]),
                        il.const(2, imm)
                        )
        il.append(
            il.store(addr_size, offset,
                     il.reg(addr_size, op[0])
                     )
        )

    @staticmethod
    def sb(il, op, imm):
        offset = il.add(addr_size,
                        il.reg(addr_size, op[1]),
                        il.const(1, imm)
                        )
        il.append(
            il.store(addr_size, offset,
                     il.reg(addr_size, op[0])
                     )
        )

    @staticmethod
    def lb(il, op, imm):
        offset = il.add(addr_size,
                        il.reg(addr_size, op[1]),
                        il.sign_extend(2, il.const(1, imm))
                        )
        il.append(
            il.set_reg(addr_size, op[0],
                       il.load(1, offset)
                       )
        )

    @staticmethod
    def lbu(il, op, imm):
        offset = il.add(addr_size,
                        il.reg(addr_size, op[1]),
                        il.sign_extend(2, il.const(1, imm)))
        il.append(
            il.set_reg(addr_size, op[0],
                       il.zero_extend(addr_size, il.load(1, offset))
                       )
        )

    @staticmethod
    def lh(il, op, imm):
        offset = il.add(addr_size,
                        il.reg(addr_size, op[1]),
                        il.sign_extend(2, il.const(2, imm)))
        il.append(
            il.set_reg(addr_size, op[0],
                       il.load(2, offset)
                       )
        )

    @staticmethod
    def lhu(il, op, imm):
        offset = il.add(addr_size,
                        il.reg(addr_size, op[1]),
                        il.zero_extend(22, il.const(2, imm))
                        )
        il.append(
            il.set_reg(addr_size, op[0],
                       il.zero_extend(addr_size, il.load(16, offset))
                       )
        )

    @staticmethod
    def lw(il, op, imm):
        offset = il.add(addr_size,
                        il.reg(addr_size, op[1]),
                        il.const(addr_size, imm)
                        )
        il.append(
            il.set_reg(addr_size, op[0],
                       il.load(addr_size, offset)
                       )
        )

    @staticmethod
    def mv(il, op, imm):

        if op[1] == 'zero':
            il.append(
                il.set_reg(addr_size, op[0],
                           il.const(addr_size, 0)
                           )
            )
        else:
            il.append(
                il.set_reg(addr_size, op[0],
                           il.reg(addr_size, op[1])
                           )
            )

    @staticmethod
    def slt(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.compare_signed_less_than(addr_size,
                                                   il.reg(addr_size, op[1]),
                                                   il.reg(addr_size, op[2])
                                                   )
                       )
        )

    @staticmethod
    def sltu(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.compare_unsigned_less_than(addr_size,
                                                     il.reg(addr_size, op[1]),
                                                     il.reg(addr_size, op[2])
                                                     )
                       )
        )

    @staticmethod
    def slti(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.compare_signed_less_than(addr_size,
                                                   il.reg(addr_size, op[1]),
                                                   il.const(addr_size, imm)
                                                   )
                       )
        )

    @staticmethod
    def sltiu(il, op, imm):
        il.append(
            il.set_reg(addr_size, op[0],
                       il.compare_unsigned_less_than(addr_size,
                                                     il.reg(addr_size, op[1]),
                                                     il.const(addr_size, imm)
                                                     )
                       )
        )

    @staticmethod
    def ecall(il, op, imm):
        il.append(il.system_call())

    @staticmethod
    def ebreak(il, op, imm):
        il.append(il.breakpoint())

    @staticmethod
    def nop(il, op, imm):
        il.append(il.nop())
