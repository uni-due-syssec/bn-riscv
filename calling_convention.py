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
"""
Specifies Calling conventions used on RISC-V architectures.

A calling convention for C compilers is specified here:
https://riscv.org/wp-content/uploads/2015/01/riscv-calling.pdf
"""

from binaryninja import CallingConvention


class RVGCallingConvention(CallingConvention):
    name = "RVG"
    global_pointer_reg = 'gp'
    caller_saved_regs = (
        'ra',
        't0',
        't1',
        't2',
        't3',
        't4',
        't5',
        't6',
        'a0',
        'a1',
        'a2',
        'a3',
        'a4',
        'a5',
        'a6',
        'a7',
        'ft0',
        'ft1',
        'ft2',
        'ft3',
        'ft4',
        'ft5',
        'ft6',
        'ft7',
        'ft8',
        'ft9',
        'ft10',
        'ft11',
        'fa0',
        'fa1',
        'fa2',
        'fa3',
        'fa4',
        'fa5',
        'fa6',
        'fa7',
    )
    callee_saved_regs = (
        'sp',
        's0',
        's1',
        's2',
        's3',
        's4',
        's5',
        's6',
        's7',
        's8',
        's9',
        's10',
        's11',
        'fs0',
        'fs1',
        'fs2',
        'fs3',
        'fs4',
        'fs5',
        'fs6',
        'fs7',
        'fs8',
        'fs9',
        'fs10',
        'fs11',
    )

    int_arg_regs = ('a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7')
    int_return_reg = 'a0'
    high_int_return_reg = 'a1'

    float_arg_regs = ('fa0', 'fa1', 'fa2', 'fa3', 'fa4', 'fa5', 'fa6')
    float_return_arg = 'fa0'
    high_float_return_arg = 'fa1'

    implicitly_defined_regs = ('tp', 'gp')
