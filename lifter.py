# Copyright 2020 Katharina Utz <katharina.utz@stud.uni-due.de>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from binaryninja import LLIL_TEMP, Architecture, LowLevelILLabel, log_error, log_warn

# TODO: make sure all expressions are lifted correctly for risc-v 64-bit

_unliftable = set()


class Lifter:
    def __init__(self, addr_size, arch_name='riscv'):
        self.arch_name = arch_name
        self.addr_size = addr_size

    def lift(self, il, instr, mnemonic):
        """
        main entry point for lifting instruction to LLIL
        """

        if mnemonic == 'or':
            mnemonic = 'or_expr'
        elif mnemonic == 'c.or':
            mnemonic = 'c.or_expr'
        elif mnemonic == 'and':
            mnemonic = 'and_expr'
        elif mnemonic == 'c.and':
            mnemonic = 'c.and_expr'
        elif mnemonic == 'not':
            mnemonic = 'not_expr'
        elif mnemonic == 'c.not':
            mnemonic = 'c.not_expr'

        # we need this to handle instructions with a '.' in the middle (e.g., "sext.w")
        mnemonic = mnemonic.replace(".", "_")

        handler = None
        ops = instr.operands

        if hasattr(self, mnemonic):
            # regular instruction -> lookup the function in the lifter
            handler = getattr(self, mnemonic)
        elif mnemonic.startswith("c_"):
            # compressed instruction prefix

            if hasattr(self, "c_" + mnemonic[2:]):
                # check if we have a lifter function for the compressed instruction
                handler = getattr(self, "c_" + mnemonic[2:])
            elif hasattr(self, mnemonic[2:]):
                # else fall back to the uncompressed handler
                handler = getattr(self, mnemonic[2:])
                # if we have operands, compressed instructions typically follow
                # the same rule of thumb:
                # inst rX, rX, P <=> c.inst rX, P

                if ops:
                    ops = [ops[0]] + ops

        if handler is not None:
            try:
                handler(il, ops, instr.imm)
            except Exception:
                log_error(
                    f"failed to lift instruction {mnemonic}@{il.current_address:#x} with handler {handler!r}"
                )
                raise
        else:
            # print unimplemented mnemonics as warning, but just once

            if mnemonic not in _unliftable:
                log_warn(f"[RISCV] cannot lift instruction: {mnemonic}")
                _unliftable.add(mnemonic)

            il.append(il.unimplemented())

    def condBranch(self, il, cond, imm):
        """
        generic helper/lifter for all conditional branches
        """
        dest = il.add(
            self.addr_size, il.const(self.addr_size, il.current_address),
            il.sign_extend(self.addr_size, il.const(self.addr_size, imm)))

        t = il.get_label_for_address(Architecture[self.arch_name],
                                     il.current_address + imm)

        if t is None:
            t = LowLevelILLabel()
            indirect = True
        else:
            indirect = False

        f_label_found = True

        f = il.get_label_for_address(Architecture[self.arch_name],
                                     il.current_address + 4)

        if f is None:
            f = LowLevelILLabel()
            f_label_found = False

        il.append(il.if_expr(cond, t, f))

        if indirect:
            il.mark_label(t)
            il.append(il.jump(dest))

        if not f_label_found:
            il.mark_label(f)

    def jal(self, il, op, imm):

        if len(op) < 1:
            ret_adr = 'ra'
        else:
            ret_adr = op[0]

        label = il.get_label_for_address(Architecture[self.arch_name],
                                         il.current_address + imm)

        if ret_adr != 'zero':
            il.append(
                il.set_reg(self.addr_size, ret_adr,
                           il.const(self.addr_size, il.current_address + 4)))

        if label is not None:
            il.append(il.goto(label))
        else:
            il.append(
                il.call(il.const(self.addr_size, il.current_address + imm)))

    def j(self, il, op, imm):
        label = il.get_label_for_address(Architecture[self.arch_name],
                                         il.current_address + imm)

        if label is not None:
            il.append(il.goto(label))
        else:
            il.append(
                il.jump(il.const(self.addr_size, il.current_address + imm)))

    def jr(self, il, op, imm):
        il.append(il.jump(il.reg(self.addr_size, op[0])))

    def jalr(self, il, op, imm, inst_size=4):

        if len(op) < 2:
            ret_adr = 'ra'
            base = op[0]
        else:
            ret_adr = op[0]
            base = op[1]

        # the zero register acts as a sink-hole for data, any write to it is
        # ignored, so we can just omit lifting this to LLIL altogether.

        if ret_adr != 'zero':
            # copy base register to temp
            il.append(
                il.set_reg(self.addr_size, LLIL_TEMP(0),
                           il.reg(self.addr_size, base)))

            # compute return address and store to ret_addr register
            il.append(
                il.set_reg(
                    self.addr_size, ret_adr,
                    il.const(self.addr_size, il.current_address + inst_size)))

        # compute the jump target
        il.append(
            il.set_reg(
                self.addr_size, LLIL_TEMP(0),
                il.and_expr(
                    self.addr_size,
                    il.add(self.addr_size, il.reg(self.addr_size,
                                                  LLIL_TEMP(0)),
                           il.const(self.addr_size, imm)),
                    il.neg_expr(self.addr_size, il.const(self.addr_size, 2)))))

        il.append(il.call(il.reg(self.addr_size, LLIL_TEMP(0))))

    def c_jalr(self, il, op, imm):
        self.jalr(il, op, imm, inst_size=2)

    def ret(self, il, op, imm):
        il.append(
            il.ret(
                il.and_expr(
                    self.addr_size, il.reg(self.addr_size, 'ra'),
                    il.neg_expr(self.addr_size, il.const(self.addr_size, 2)))))
        il.append(il.pop(self.addr_size))

    def beq(self, il, op, imm):
        cond = il.compare_equal(self.addr_size, il.reg(self.addr_size, op[0]),
                                il.reg(self.addr_size, op[1]))
        self.condBranch(il, cond, imm)

    def beqz(self, il, op, imm):
        cond = il.compare_equal(self.addr_size, il.reg(self.addr_size, op[0]),
                                il.const(self.addr_size, 0))
        self.condBranch(il, cond, imm)

    def bne(self, il, op, imm):
        cond = il.compare_not_equal(self.addr_size,
                                    il.reg(self.addr_size, op[0]),
                                    il.reg(self.addr_size, op[1]))
        self.condBranch(il, cond, imm)

    def bnez(self, il, op, imm):
        cond = il.compare_not_equal(self.addr_size,
                                    il.reg(self.addr_size, op[0]),
                                    il.const(self.addr_size, 0))
        self.condBranch(il, cond, imm)

    def blt(self, il, op, imm):
        cond = il.compare_signed_less_than(self.addr_size,
                                           il.reg(self.addr_size, op[0]),
                                           il.reg(self.addr_size, op[1]))
        self.condBranch(il, cond, imm)

    def bltu(self, il, op, imm):
        cond = il.compare_unsigned_less_than(self.addr_size,
                                             il.reg(self.addr_size, op[0]),
                                             il.reg(self.addr_size, op[1]))
        self.condBranch(il, cond, imm)

    def bltz(self, il, op, imm):
        cond = il.compare_signed_less_than(self.addr_size,
                                           il.reg(self.addr_size, op[0]),
                                           il.const(self.addr_size, 0))
        self.condBranch(il, cond, imm)

    def bgtz(self, il, op, imm):
        cond = il.compare_signed_less_than(self.addr_size,
                                           il.const(self.addr_size, 0),
                                           il.reg(self.addr_size, op[0]))
        self.condBranch(il, cond, imm)

    def bge(self, il, op, imm):
        cond = il.compare_signed_greater_equal(self.addr_size,
                                               il.reg(self.addr_size, op[0]),
                                               il.reg(self.addr_size, op[1]))
        self.condBranch(il, cond, imm)

    def bgeu(self, il, op, imm):
        cond = il.compare_unsigned_greater_equal(self.addr_size,
                                                 il.reg(self.addr_size, op[0]),
                                                 il.reg(self.addr_size, op[0]))
        self.condBranch(il, cond, imm)

    def blez(self, il, op, imm):
        cond = il.compare_signed_greater_equal(self.addr_size,
                                               il.const(self.addr_size, 0),
                                               il.reg(self.addr_size, op[0]))
        self.condBranch(il, cond, imm)

    def bgez(self, il, op, imm):
        cond = il.compare_unsigned_greater_equal(self.addr_size,
                                                 il.reg(self.addr_size, op[0]),
                                                 il.const(self.addr_size, 0))
        self.condBranch(il, cond, imm)

    def add(self, il, op, imm):
        if op[1] == 'zero':
            computation = il.reg(self.addr_size, op[2])
        elif op[2] == 'zero':
            computation = il.reg(self.addr_size, op[1])
        else:
            computation = il.add(self.addr_size, il.reg(self.addr_size, op[1]),
                                 il.reg(self.addr_size, op[2]))

        if op[0] == 'zero':
            il.append(il.nop())
        else:
            il.append(il.set_reg(self.addr_size, op[0], computation))

    def addw(self, il, op, imm):
        if op[1] == 'zero':
            computation = il.reg(4, op[2])
        elif op[2] == 'zero':
            computation = il.reg(4, op[1])
        else:
            computation = il.add(4, il.reg(self.addr_size, op[1]),
                                 il.reg(self.addr_size, op[2]))

        if op[0] == 'zero':
            il.append(il.nop())
        else:
            il.append(
                il.set_reg(self.addr_size, op[0],
                           il.sign_extend(self.addr_size, computation)))

    def addi(self, il, op, imm):
        if op[1] != 'zero':
            computation = il.add(self.addr_size, il.reg(self.addr_size, op[1]),
                                 il.const(self.addr_size, imm))
        else:
            # addi rd, zero, 5 => rd == 5
            computation = il.const(self.addr_size, imm)

        if op[0] == 'zero':
            il.append(il.nop())
        else:
            il.append(il.set_reg(self.addr_size, op[0], computation))

    def c_addi4spn(self, il, op, imm):
        self.addi(il, [op[0], 'sp'], imm)

    def c_addi16sp(self, il, op, imm):
        il.append(
            il.add(self.addr_size, il.reg(self.addr_size, 'sp'),
                   il.const(self.addr_size, imm)))

    def addiw(self, il, op, imm):
        if op[1] != 'zero':
            computation = il.add(4,
                                 il.low_part(4, il.reg(self.addr_size, op[1])),
                                 il.const(4, imm))
        else:
            # addi rd, zero, 5 => rd == 5
            computation = il.const(4, imm)

        computation = il.sign_extend(self.addr_size, computation)

        if op[0] == 'zero':
            il.append(il.nop())
        else:
            il.append(il.set_reg(self.addr_size, op[0], computation))

    def sext_w(self, il, op, imm):
        il.append(
            il.set_reg(self.addr_size, op[0],
                       il.sign_extend(self.addr_size, il.reg(4, op[1]))))

    def sub(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.sub(self.addr_size, il.reg(self.addr_size, op[1]),
                       il.reg(self.addr_size, op[2]))))

    def subw(self, il, op, imm):
        if op[1] == 'zero':
            computation = il.reg(4, op[2])
        elif op[2] == 'zero':
            computation = il.reg(4, op[1])
        else:
            computation = il.sub(4, il.reg(self.addr_size, op[1]),
                                 il.reg(self.addr_size, op[2]))

        if op[0] == 'zero':
            il.append(il.nop())
        else:
            il.append(
                il.set_reg(self.addr_size, op[0],
                           il.sign_extend(self.addr_size, computation)))

    def neg(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.neg_expr(self.addr_size, il.reg(self.addr_size, op[1]))))

    def negw(self, il, op, imm):
        """RV64 only - negate 32-bit value in register"""
        # self.subw(il, [op[0], 'zero', op[1]])
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.sign_extend(self.addr_size,
                               il.neg_expr(4, il.reg(self.addr_size, op[1])))))

    def not_expr(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.not_expr(self.addr_size, il.reg(self.addr_size, op[1]))))

    def mul(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.mult(self.addr_size, il.reg(self.addr_size, op[1]),
                        il.reg(self.addr_size, op[2]))))

    def div(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.div_signed(self.addr_size, il.reg(self.addr_size, op[1]),
                              il.reg(self.addr_size, op[2]))))

    def divu(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.div_unsigned(self.addr_size, il.reg(self.addr_size, op[1]),
                                il.reg(self.addr_size, op[2]))))

    def divw(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.sign_extend(
                    self.addr_size,
                    il.div_signed(4, il.reg(self.addr_size, op[1]),
                                  il.reg(self.addr_size, op[2])))))

    def divuw(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.sign_extend(
                    self.addr_size,
                    il.div_unsigned(4, il.reg(self.addr_size, op[1]),
                                    il.reg(self.addr_size, op[2])))))

    def rem(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.mod_signed(self.addr_size, il.reg(self.addr_size, op[1]),
                              il.reg(self.addr_size, op[2]))))

    def remu(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.mod_unsigned(self.addr_size, il.reg(self.addr_size, op[1]),
                                il.reg(self.addr_size, op[2]))))

    def remw(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.sign_extend(
                    self.addr_size,
                    il.mod_signed(4, il.reg(self.addr_size, op[1]),
                                  il.reg(self.addr_size, op[2])))))

    def remuw(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.sign_extend(
                    self.addr_size,
                    il.mod_unsigned(4, il.reg(self.addr_size, op[1]),
                                    il.reg(self.addr_size, op[2])))))

    def and_expr(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.and_expr(self.addr_size, il.reg(self.addr_size, op[1]),
                            il.reg(self.addr_size, op[2]))))

    def andi(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.and_expr(
                    self.addr_size, il.reg(self.addr_size, op[1]),
                    il.sign_extend(
                        self.addr_size,
                        il.and_expr(2, il.const(2, imm), il.const(2,
                                                                  0xfff))))))

    def or_expr(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.or_expr(self.addr_size, il.reg(self.addr_size, op[1]),
                           il.reg(self.addr_size, op[2]))))

    def ori(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.or_expr(
                    self.addr_size, il.reg(self.addr_size, op[1]),
                    il.sign_extend(
                        self.addr_size,
                        il.and_expr(2, il.const(2, imm), il.const(2,
                                                                  0xfff))))))

    def xor(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.xor_expr(self.addr_size, il.reg(self.addr_size, op[1]),
                            il.reg(self.addr_size, op[2]))))

    def xori(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.xor_expr(
                    self.addr_size, il.reg(self.addr_size, op[1]),
                    il.sign_extend(
                        self.addr_size,
                        il.and_expr(2, il.const(2, imm), il.const(2,
                                                                  0xfff))))))

    def sll(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.shift_left(self.addr_size, il.reg(self.addr_size, op[1]),
                              il.reg(self.addr_size, op[2]))))

    def sllw(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.sign_extend(
                    self.addr_size,
                    il.shift_left(4, il.reg(self.addr_size, op[1]),
                                  il.reg(self.addr_size, op[2])))))

    def slli(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.shift_left(self.addr_size, il.reg(self.addr_size, op[1]),
                              il.const(1, imm))))

    def slliw(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.sign_extend(
                    self.addr_size,
                    il.shift_left(4, il.reg(self.addr_size, op[1]),
                                  il.const(1, imm)))))

    def srl(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.logical_shift_right(self.addr_size,
                                       il.reg(self.addr_size, op[1]),
                                       il.reg(self.addr_size, op[2]))))

    def srlw(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.sign_extend(
                    self.addr_size,
                    il.logical_shift_right(4, il.reg(self.addr_size, op[1]),
                                           il.reg(self.addr_size, op[2])))))

    def srli(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.logical_shift_right(self.addr_size,
                                       il.reg(self.addr_size, op[1]),
                                       il.const(1, imm))))

    def srliw(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.sign_extend(
                    self.addr_size,
                    il.logical_shift_right(4, il.reg(self.addr_size, op[1]),
                                           il.const(1, imm)))))

    def sra(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.arith_shift_right(self.addr_size,
                                     il.reg(self.addr_size, op[1]),
                                     il.reg(self.addr_size, op[2]))))

    def sraw(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.sign_extend(
                    self.addr_size,
                    il.arith_shift_right(4, il.reg(self.addr_size, op[1]),
                                         il.reg(self.addr_size, op[2])))))

    def srai(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.arith_shift_right(self.addr_size,
                                     il.reg(self.addr_size, op[1]),
                                     il.const(self.addr_size, imm))))

    def sraiw(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.sign_extend(
                    self.addr_size,
                    il.arith_shift_right(4, il.reg(self.addr_size, op[1]),
                                         il.const(1, imm)))))

    def lui(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size,
                op[0],
                # il.shift_left(self.addr_size,
                #               il.zero_extend(self.addr_size, il.const(3, imm)),
                #               # il.const(self.addr_size, imm)),
                #               il.const(self.addr_size, 12))
                il.const(self.addr_size, imm)))

    def c_li(self, il, op, imm):
        il.append(
            il.set_reg(self.addr_size, op[0], il.const(self.addr_size, imm)))

    def auipc(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.const(self.addr_size, (il.current_address + (imm << 12)) %
                         (2**(8 * self.addr_size)))))

    def _store(self, il, op, imm, size):
        offset = il.add(self.addr_size, il.reg(self.addr_size, op[1]),
                        il.const(self.addr_size, imm))

        if op[0] == 'zero':
            val = il.const(self.addr_size, 0)
        else:
            val = il.reg(self.addr_size, op[0])

        il.append(il.store(size, offset, val))

    def sd(self, il, op, imm):
        self._store(il, op, imm, 8)

    def sw(self, il, op, imm):
        self._store(il, op, imm, 4)

    def sh(self, il, op, imm):
        self._store(il, op, imm, 2)

    def sb(self, il, op, imm):
        self._store(il, op, imm, 1)

    def c_sdsp(self, il, op, imm):
        self.sd(il, [op[0], "sp"], imm)

    def sc_w(self, il, op, imm):
        self._store(il, op, imm, 4)

    def sc_d(self, il, op, imm):
        self._store(il, op, imm, 8)

    def _load(self, il, op, imm, size, extend):
        """
        generic helper for load instructions of various sizes
        """
        offset = il.add(self.addr_size, il.reg(self.addr_size, op[1]),
                        il.sign_extend(2, il.const(1, imm)))
        il.append(
            il.set_reg(self.addr_size, op[0],
                       extend(self.addr_size, il.load(size, offset))))

    def lb(self, il, op, imm):
        self._load(il, op, imm, 1, il.sign_extend)

    def lbu(self, il, op, imm):
        self._load(il, op, imm, 1, il.zero_extend)

    def lh(self, il, op, imm):
        self._load(il, op, imm, 2, il.sign_extend)

    def lhu(self, il, op, imm):
        self._load(il, op, imm, 2, il.zero_extend)

    def lw(self, il, op, imm):
        if self.addr_size == 4:
            self._load(il, op, imm, 4, lambda x, y: y)
        else:
            self._load(il, op, imm, 4, il.sign_extend)

    def lwu(self, il, op, imm):
        if self.addr_size == 4:
            self._load(il, op, imm, 4, lambda x, y: y)
        else:
            self._load(il, op, imm, 4, il.zero_extend)

    def ld(self, il, op, imm):
        if self.addr_size == 8:
            self._load(il, op, imm, 8, lambda x, y: y)
        else:
            self._load(il, op, imm, 8, il.sign_extend)

    def c_ldsp(self, il, op, imm):
        self.ld(il, [op[0], "sp"], imm)

    def lr_w(self, il, op, imm):
        self.lw(il, op, imm)

    def lr_d(self, il, op, imm):
        self.ld(il, op, imm)

    def mv(self, il, op, imm):

        if op[1] == 'zero':
            il.append(
                il.set_reg(self.addr_size, op[0], il.const(self.addr_size, 0)))
        else:
            il.append(
                il.set_reg(self.addr_size, op[0],
                           il.reg(self.addr_size, op[1])))

    # we need this, s.t., the lookup in the lift function above doesn't prepend
    # the 0 argument needlessly
    c_mv = mv

    def slt(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.compare_signed_less_than(self.addr_size,
                                            il.reg(self.addr_size, op[1]),
                                            il.reg(self.addr_size, op[2]))))

    def sltu(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.compare_unsigned_less_than(self.addr_size,
                                              il.reg(self.addr_size, op[1]),
                                              il.reg(self.addr_size, op[2]))))

    def slti(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.compare_signed_less_than(self.addr_size,
                                            il.reg(self.addr_size, op[1]),
                                            il.const(self.addr_size, imm))))

    def sltiu(self, il, op, imm):
        il.append(
            il.set_reg(
                self.addr_size, op[0],
                il.compare_unsigned_less_than(self.addr_size,
                                              il.reg(self.addr_size, op[1]),
                                              il.const(self.addr_size, imm))))

    def seqz(self, il, op, imm):
        """
        Set if = zero
        alias for: sltiu rd, rs, 1
        """
        self.sltiu(il, op, 1)
        # TODO: I think we can instead of calling the alias we could use a
        # "more optimized" lifting here?
        # il.append

    def snez(self, il, op, imm):
        """
        Set if != zero
        alias for sltu rd, x0, rs
        """
        self.sltu(il, [op[0], 'zero', op[1]], None)

    def sltz(self, il, op, imm):
        self.slt(il, [op[0], op[1], 'zero'], imm)

    def sgtz(self, il, op, imm):
        self.slt(il, [op[0], 'zero', op[1]], imm)

    def ecall(self, il, op, imm):
        il.append(il.system_call())

    def ebreak(self, il, op, imm):
        il.append(il.breakpoint())

    def nop(self, il, op, imm):
        il.append(il.nop())

    def csrw(self, il, op, imm):
        il.append(il.set_reg(self.addr_size, op[0], il.undefined()))

    # floating point instructions

    def fld(self, il, op, imm):
        self._load(il, op, imm, 8, lambda x, y: y)

    def fsd(self, il, op, imm):
        self._store(il, op, imm, 8)
