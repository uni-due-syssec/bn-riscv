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

from binaryninja import (Architecture, BranchType, Endianness, InstructionInfo,
                         RegisterInfo)

from .instruction import RVDisassembler, gen_token
from .lifter import Lifter

branch_ins = set([
    'beq', 'bne', 'beqz', 'bnez', 'bge', 'bgeu', 'blt', 'bltu', 'blez', 'bgez',
    'bltz', 'bgtz'
])

for bi in list(branch_ins):  # use list() to clone here
    if not bi.startswith('c.'):
        branch_ins.add('c.' + bi)

direct_jump_ins = set(['j', 'c.j'])
indirect_jump_ins = set(['jr', 'c.jr'])
direct_call_ins = set(['jal', 'c.jal'])
indirect_call_ins = set(['jalr', 'c.jalr'])


class RISCV(Architecture):
    name = "riscv"

    address_size = 4
    default_int_size = 4
    # TODO: This actually depends on whether the F, D, Q extension is
    # implemented, but we'll just assume it is the Q extension (128 bit)
    default_float_size = 16

    # TODO: not sure this is true for all extensions?
    max_instr_length = 4

    endianness = Endianness.LittleEndian

    disassembler = RVDisassembler(address_size)
    lifter = Lifter(address_size)

    # we are using the ABI names here, as those are also the register names
    # returned by capstone.
    regs = {
        # x0 - hard-wired zero
        "zero": RegisterInfo("zero", address_size),
        # x1 - return address (caller saved)
        "ra": RegisterInfo("ra", address_size),
        # x2 - stack pointer (callee saved)
        "sp": RegisterInfo("sp", address_size),
        # x3 - global pointer
        "gp": RegisterInfo("gp", address_size),
        # x4 - threat pointer
        "tp": RegisterInfo("tp", address_size),
        # x5-7 - temporaries (caller saved)
        "t0": RegisterInfo("t0", address_size),
        "t1": RegisterInfo("t1", address_size),
        "t2": RegisterInfo("t2", address_size),
        # x8 - saved register / frame pointer (caller saved)
        "s0": RegisterInfo("s0", address_size),
        # x9 - saved register
        "s1": RegisterInfo("s1", address_size),
        # x10-x11 - first function argument and return value (caller saved)
        "a0": RegisterInfo("a0", address_size),
        "a1": RegisterInfo("a1", address_size),
        # x12-17 - function arguments (caller saved)
        "a2": RegisterInfo("a2", address_size),
        "a3": RegisterInfo("a3", address_size),
        "a4": RegisterInfo("a4", address_size),
        "a5": RegisterInfo("a5", address_size),
        "a6": RegisterInfo("a6", address_size),
        "a7": RegisterInfo("a7", address_size),
        # x18-27 - saved registers (caller saved)
        "s2": RegisterInfo("s2", address_size),
        "s3": RegisterInfo("s3", address_size),
        "s4": RegisterInfo("s4", address_size),
        "s5": RegisterInfo("s5", address_size),
        "s6": RegisterInfo("s6", address_size),
        "s7": RegisterInfo("s7", address_size),
        "s8": RegisterInfo("s8", address_size),
        "s9": RegisterInfo("s9", address_size),
        "s10": RegisterInfo("s10", address_size),
        "s11": RegisterInfo("s11", address_size),
        # x28-31 - temporaries
        "t3": RegisterInfo("t3", address_size),
        "t4": RegisterInfo("t4", address_size),
        "t5": RegisterInfo("t5", address_size),
        "t6": RegisterInfo("t6", address_size),
        # pc (caller saved)
        "pc": RegisterInfo("pc", address_size),

        # f0-7 - FP temporaries (caller saved)
        "ft0": RegisterInfo("ft0", default_float_size),
        "ft1": RegisterInfo("ft1", default_float_size),
        "ft2": RegisterInfo("ft2", default_float_size),
        "ft3": RegisterInfo("ft3", default_float_size),
        "ft4": RegisterInfo("ft4", default_float_size),
        "ft5": RegisterInfo("ft5", default_float_size),
        "ft6": RegisterInfo("ft6", default_float_size),
        "ft7": RegisterInfo("ft7", default_float_size),
        # f8-9 - FP saved registers (callee saved)
        "fs0": RegisterInfo("fs0", default_float_size),
        "fs1": RegisterInfo("fs1", default_float_size),
        # f10-11 - FP arguments/return values (caller saved)
        "fa0": RegisterInfo("fa0", default_float_size),
        "fa1": RegisterInfo("fa1", default_float_size),
        # f12-17 - FP arguments (caller saved)
        "fa2": RegisterInfo("fa2", default_float_size),
        "fa3": RegisterInfo("fa3", default_float_size),
        "fa4": RegisterInfo("fa4", default_float_size),
        "fa5": RegisterInfo("fa5", default_float_size),
        "fa6": RegisterInfo("fa6", default_float_size),
        "fa7": RegisterInfo("fa7", default_float_size),
        # f18–27 - FP saved registers (callee saved)
        "fs2": RegisterInfo("fs2", default_float_size),
        "fs3": RegisterInfo("fs3", default_float_size),
        "fs4": RegisterInfo("fs4", default_float_size),
        "fs5": RegisterInfo("fs5", default_float_size),
        "fs6": RegisterInfo("fs6", default_float_size),
        "fs7": RegisterInfo("fs7", default_float_size),
        "fs8": RegisterInfo("fs8", default_float_size),
        "fs9": RegisterInfo("fs9", default_float_size),
        "fs10": RegisterInfo("fs10", default_float_size),
        "fs11": RegisterInfo("fs11", default_float_size),
        # f28-31 - FP temporaries (caller saved)
        "ft8": RegisterInfo("ft8", default_float_size),
        "ft9": RegisterInfo("ft9", default_float_size),
        "ft10": RegisterInfo("ft10", default_float_size),
        "ft11": RegisterInfo("ft11", default_float_size),
    }

    stack_pointer = "sp"

    def get_instruction_info(self, data, addr):

        instr = self.disassembler.decode(data, addr)

        if instr is None:
            return None

        result = InstructionInfo()
        result.length = instr.size

        dest = None

        if instr.imm is not None:
            dest = addr + instr.imm

        if instr.name == 'ret' or self._looks_like_ret(instr):
            result.add_branch(BranchType.FunctionReturn)
        elif instr.name in branch_ins:
            result.add_branch(BranchType.TrueBranch, dest)
            result.add_branch(BranchType.FalseBranch, addr + instr.size)
        elif instr.name in direct_jump_ins:
            result.add_branch(BranchType.UnconditionalBranch, dest)
        elif instr.name in indirect_jump_ins:
            result.add_branch(BranchType.UnresolvedBranch)
        elif instr.name in direct_call_ins:
            result.add_branch(BranchType.CallDestination, dest)
        elif instr.name in indirect_call_ins:
            result.add_branch(BranchType.UnresolvedBranch)

        return result

    def _looks_like_ret(self, instr):
        """
        Check for jump instruction that look like functions returns.
        """
        # any register jump to 'ra' the return address register, is probably a 
        # function return.

        if (instr.name == 'jalr' and len(instr.operands) == 2 and
                instr.operands[0] == 'zero'
                and instr.operands[1] == 'ra' and not instr.imm):
            # if jalr does not link into zero, then something weird
            # is going on and we don't want to mark this as a return.
            # similarly if a offset is added (via imm) to the ra register,
            # then this also doesn't look like a function return.
            return True
        elif (instr.name == 'jr' and instr.operands[0] == 'ra'
              and not instr.imm):
            return True

        return False

    def get_instruction_text(self, data, addr):

        instr = self.disassembler.decode(data, addr)

        if instr is None:
            return None

        tokens = gen_token(instr)

        return tokens, instr.size

    def get_instruction_low_level_il(self, data, addr, il):

        instr = self.disassembler.decode(data, addr)

        if instr is None:
            return None
        self.lifter.lift(il, instr, instr.name)

        return instr.size


class RISCV64(RISCV):
    name = "riscv64"

    address_size = 8
    default_int_size = 4

    disassembler = RVDisassembler(address_size)
    lifter = Lifter(address_size)

    regs = {
        k: (RegisterInfo(k, 8) if v.size == 4 else RegisterInfo(k, v.size))
        for k, v in RISCV.regs.items()
    }
