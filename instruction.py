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

import capstone
from capstone import (CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCV64,
                      CS_MODE_RISCVC)
from capstone.riscv import RISCV_OP_IMM, RISCV_OP_MEM, RISCV_OP_REG

from binaryninja import InstructionTextToken, InstructionTextTokenType

_OFFSET = set([
    'beq', 'beqz', 'bne', 'bnez', 'bge', 'blez', 'bgez', 'blt', 'bltz', 'bgtz',
    'bltu', 'bgeu', 'jal', 'jalr', 'j', 'jr'
])


class RVInstruction:
    __slots__ = 'size', 'name', 'op', 'imm', 'imm_val'

    def __init__(self, size, name, op, imm, imm_val):
        self.size = size
        self.name = name
        self.op = op
        self.imm = imm
        self.imm_val = imm_val


class RVDisassembler:
    """
    Wraps a RISC-V disassembler
    """
    def __init__(self, mode):
        if mode == 4:
            self._mode = CS_MODE_RISCV32
        elif mode == 8:
            self._mode = CS_MODE_RISCV64

        # TODO: enable RISC-V compressed ISA
        # self._mode |= CS_MODE_RISCVC

        # initialize capstone
        self._md = capstone.Cs(CS_ARCH_RISCV, self._mode)
        # enabled capstone detailed mode
        self._md.detail = True

    def decode(self, data, addr):
        op = ""
        imm = 0

        for insn in self._md.disasm(data, addr):
            size = insn.size
            name = insn.mnemonic
            imm_val = False

            if len(insn.operands) > 0:
                for i in insn.operands:
                    if i.type == RISCV_OP_REG:
                        op += " " + (insn.reg_name(i.value.reg))
                    elif i.type == RISCV_OP_IMM:
                        imm = i.value.imm
                        imm_val = True
                    elif i.type == RISCV_OP_MEM:
                        if i.mem.base != 0:
                            op += " " + insn.reg_name(i.mem.base)
                        if i.mem.disp != 0:
                            imm = i.mem.disp
                            imm_val = True

            return RVInstruction(size, name, op, imm, imm_val)


def gen_token(instr):
    tokens = [
        InstructionTextToken(InstructionTextTokenType.InstructionToken,
                             "{:6} ".format(instr.name))
    ]
    operands = instr.op.split()
    for i in operands:
        tokens.append(
            InstructionTextToken(InstructionTextTokenType.TextToken, " "))
        tokens.append(
            InstructionTextToken(InstructionTextTokenType.RegisterToken, i))

    if instr.imm_val:
        tokens.append(
            InstructionTextToken(InstructionTextTokenType.TextToken, " "))
        if instr.name in _OFFSET:
            tokens.append(
                InstructionTextToken(
                    InstructionTextTokenType.PossibleAddressToken,
                    hex(instr.imm),
                    value=instr.imm))
        else:
            tokens.append(
                InstructionTextToken(InstructionTextTokenType.IntegerToken,
                                     hex(instr.imm),
                                     value=instr.imm))
    return tokens
