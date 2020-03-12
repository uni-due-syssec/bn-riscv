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


from capstone import *
from capstone.riscv import *
from collections import namedtuple
from binaryninja import InstructionTextToken, InstructionTextTokenType


offset = [
    'beq', 'beqz', 'bne', 'bnez', 'bge', 'blez', 'bgez', 'blt',
    'bltz', 'bgtz', 'bltu', 'bgeu', 'jal', 'jalr', 'j', 'jr'
]


def decode(data, addr, mode):

    instr = namedtuple('Instruction', 'size name op imm imm_val')
    op = ""
    imm = 0
    if mode == 4:
        mode = CS_MODE_RISCV32
    elif mode == 8:
        mode = CS_MODE_RISCV64

    # TODO: enable RISC-V compressed ISA 
    # mode |= CS_MODE_RISCVC

    md = Cs(CS_ARCH_RISCV, mode)
    md.detail = True

    for insn in md.disasm(data, addr):
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

        return instr(size, name, op, imm, imm_val)


def gen_token(instr):

    tokens = [InstructionTextToken(
        InstructionTextTokenType.InstructionToken,
        "{:6} ".format(
            instr.name
        )
    )]
    operands = instr.op.split()
    for i in operands:
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, " "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, i))

    if instr.imm_val:
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, " "))
        if instr.name in offset:
            tokens.append(InstructionTextToken(
                InstructionTextTokenType.PossibleAddressToken, hex(instr.imm), value=instr.imm))
        else:
            tokens.append(InstructionTextToken(
                InstructionTextTokenType.IntegerToken, hex(instr.imm), value=instr.imm))
    return tokens
