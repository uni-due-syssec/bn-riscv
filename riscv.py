from binaryninja import (Architecture, Endianness, RegisterInfo, InstructionInfo,
                         BranchType, log_info)

from .instruction import decode, gen_token
from .lifter import Lifter

branch_ins = set([
    'beq', 'bne', 'beqz', 'bnez', 'bge', 'bgeu',
    'blt', 'bltu', 'blez', 'bgez', 'bltz', 'bgtz'
])

direct_call_ins = set(['jal', 'j'])
indirect_call_ins = set(['jalr', 'jr'])

class RISCV(Architecture):
    name = "riscv"

    address_size = 4
    default_int_size = 4
    max_instr_length = 4

    endianness = Endianness.LittleEndian

    lifter = Lifter(address_size)

    regs = {
        "zero": RegisterInfo("zero", address_size),    # hard-wired zero
        "ra": RegisterInfo("ra", address_size),        # return address
        "sp": RegisterInfo("sp", address_size),        # stack pointer
        "gp": RegisterInfo("gp", address_size),        # global pointer
        "tp": RegisterInfo("tp", address_size),        # thread pointer
        "t0": RegisterInfo("t0", address_size),        # temporaries
        "t1": RegisterInfo("t1", address_size),
        "t2": RegisterInfo("t2", address_size),
        "s0": RegisterInfo("s0", address_size),        # saved register (frame pointer)
        "s1": RegisterInfo("s1", address_size),
        "a0": RegisterInfo("a0", address_size),        # return values
        "a1": RegisterInfo("a1", address_size),        # function arguments
        "a2": RegisterInfo("a2", address_size),
        "a3": RegisterInfo("a3", address_size),
        "a4": RegisterInfo("a4", address_size),
        "a5": RegisterInfo("a5", address_size),
        "a6": RegisterInfo("a6", address_size),
        "a7": RegisterInfo("a7", address_size),
        "s2": RegisterInfo("s2", address_size),        # saved registers
        "s3": RegisterInfo("s3", address_size),
        "s4": RegisterInfo("s4", address_size),
        "s5": RegisterInfo("s5", address_size),
        "s6": RegisterInfo("s6", address_size),
        "s7": RegisterInfo("s7", address_size),
        "s8": RegisterInfo("s8", address_size),
        "s9": RegisterInfo("s9", address_size),
        "s10": RegisterInfo("s10", address_size),
        "s11": RegisterInfo("s11", address_size),
        "t3": RegisterInfo("t3", address_size),        # temporaries
        "t4": RegisterInfo("t4", address_size),
        "t5": RegisterInfo("t5", address_size),
        "t6": RegisterInfo("t6", address_size),
        "pc": RegisterInfo("pc", address_size),
    }

    stack_pointer = "sp"

    def get_instruction_info(self, data, addr):

        instr = decode(data, addr, self.address_size)

        if instr is None:
            return None

        result = InstructionInfo()
        result.length = instr.size

        dest = addr + instr.imm

        if instr.name == 'ret':
            result.add_branch(BranchType.FunctionReturn)
        elif instr.name in branch_ins:
            result.add_branch(BranchType.TrueBranch, dest)
            result.add_branch(BranchType.FalseBranch, addr + 4)
        elif instr.name in direct_call_ins:
            result.add_branch(BranchType.CallDestination, dest)
        elif instr.name in indirect_call_ins:
            result.add_branch(BranchType.UnresolvedBranch)

        return result

    def get_instruction_text(self, data, addr):

        instr = decode(data, addr, self.address_size)

        if instr is None:
            return None

        tokens = gen_token(instr)

        return tokens, instr.size

    def get_instruction_low_level_il(self, data, addr, il):

        instr = decode(data, addr, self.address_size)

        if instr is None:
            return None
        else:
            self.lifter.lift(il, instr, instr.name)

        return instr.size


class RISCV64(RISCV):
    name = "riscv64"

    address_size = 8
    default_int_size = 8
