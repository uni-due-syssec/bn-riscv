from binaryninja import CallingConvention


class DefaultCallingConvention(CallingConvention):
    name = "default"
    int_arg_regs = ['a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7']
    int_return_reg = 'a0'
    high_int_return_reg = 'a1'
