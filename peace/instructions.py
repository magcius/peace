
def _make_offset_label_name(offset):
    return "lbl" + str(offset)

def _make_offset_label(offset, asm):
    name = _make_offset_label_name(offset)
    label = asm.make_label(name)
    label.address = offset
    return label

class BaseInstruction(object):
    flags = 0
    stack = 0
    opcode = None
    name   = None
    label  = None
    jumplike = False

    def __repr__(self):
        if self.opcode is None:
            return self.name
        return "%s (0x%02X%s)" % (self.name, self.opcode, self.additional_repr())

    def __len__(self):
        return 1

    def additional_repr(self):
        return ""

    def write_constants(self, pool):
        pass

    def serialize(self):
        return chr(self.opcode) + self.serialize_arguments()

    def serialize_arguments(self):
        return ""

    # Hooks for the assembler.
    def assembler_added(self, asm):
        """
        Called when the assembler adds this instruction.
        """

    def assembler_pass1(self, asm):
        """
        Called on the assembler's first pass.
        """
        asm.flags |= self.flags
        asm.stack_depth += self.stack() if callable(self.stack) else self.stack

    def assembler_pass2(self, asm, address):
        """
        Called on the assembler's second pass.
        """

def OP(opcode, base=BaseInstruction, **kw):
    return opcode, base, kw

class U1Instruction(BaseInstruction):
    arg_count = 1

    def __init__(self, *args):
        if self.arg_count != len(args):
            raise ValueError("%s takes %d argument(s). "
                             "This instance has %d argument(s)." % \
                             (self.name, self.arg_count, len(args)))

        self.arguments = args
        if self.arg_count == 1:
            self.argument = args[0]

    def serialize_arguments(self):
        return ''.join(chr(i) for i in self.arguments)

    def additional_repr(self):
        return " arg="+' '.join("0x%02X" % (a,) for a in self.arguments)

    def __len__(self):
        return 1 + self.arg_count

class LoadConstantInstruction(BaseInstruction):
    def __init__(self, constant):
        self.constant = constant

    def write_constants(self, pool):
        self._idx = pool.index_for(self.constant)

    def serialize_arguments(self):
        return chr(self._idx)

    def __len__(self):
        return 2

class JumpBase(BaseInstruction):
    jumplike = True
    def __init__(self, name):
        self.labelname = name
        self.address = None

    def assembler_pass1(self, asm):
        super(JumpBase, self).assembler_pass1(asm)
        self.label = asm.make_label(self.labelname)
        asm.jumps.append(self)

    def serialize_arguments(self):
        return "\0\0"

    def additional_repr(self):
        return" lbl=%r" % (self.labelname,)

    def __len__(self):
        return 3

class InvokeU2Instruction(BaseInstruction):
    def stack(self, methodref, num_args):
        self.methodref = methodref
        self.num_args = num_args

    def stack(self):
        return 1 - (self.num_args + 1) # push object/args; push result

    def write_constants(self, pool):
        self._methodref_idx = pool.index_for(self.methodref)

    def serialize_arguments(self):
        return struct.pack('>H', self._methodref_idx)

    def additional_repr(self):
        return ", methodref=%s, num_args=%s" % (self.methodref, self.num_args)

    def __len__(self):
        return 3

class BogusBase(BaseInstruction):
    name = "BOGUS"
    def serialize(self):
        return ""

    def __len__(self):
        return 0

class Label(BogusBase):
    def __init__(self, name):
        self.labelname = name
        self.label = None

    def assembler_pass1(self, asm):
        if self.labelname in asm.labels:
            self.label = asm.labels[self.labelname]
            asm.stack_depth = self.label.stack_depth
            asm.scope_depth = self.label.scope_depth
        else:
            # If we haven't seen the label yet, we could have to jump
            # back to it later.
            self.label = asm.make_label(self.labelname)

    def assembler_pass2(self, asm, address):
        self.label.address = address

    def additional_repr(self):
        return " lbl=%r" % (self.labelname,)

OpTable = dict(
    aaload          = OP(0x32, stack=-1),
    aastore         = OP(0x53, stack=-3),
    aconst_null     = OP(0x1, stack=+1),
    aload           = OP(0x19, stack=+1, base=U1Instruction),
    aload_0         = OP(0x2A, stack=+1),
    aload_1         = OP(0x2B, stack=+1),
    aload_2         = OP(0x2C, stack=+1),
    aload_3         = OP(0x2D, stack=+1),
    anewarray       = OP(0xBD, arg_count=2),
    arraylength     = OP(0xBE),
    astore          = OP(0x3A, stack=-1, base=U1Instruction),
    astore_0        = OP(0x4B, stack=-1),
    astore_1        = OP(0x4C, stack=-1),
    astore_2        = OP(0x4D, stack=-1),
    astore_3        = OP(0x4E, stack=-1),
    athrow          = OP(0xBF, stack=+1),
    baload          = OP(0x33, stack=-1),
    bastore         = OP(0x54, stack=-3),
    bipush          = OP(0x10, stack=+1, base=U1Instruction),
    caload          = OP(0x34, stack=-1),
    castore         = OP(0x55, stack=-3),
    checkcast       = OP(0xC0, arg_count=2),
    d2f             = OP(0x90),
    d2i             = OP(0x8E),
    d2l             = OP(0x8F),
    dadd            = OP(0x63, stack=-1),
    daload          = OP(0x31, stack=-1),
    dastore         = OP(0x52, stack=-3),
    dcmpg           = OP(0x98, stack=-1),
    dcmpl           = OP(0x97, stack=-1),
    dconst_0        = OP(0xE, stack=+1),
    dconst_1        = OP(0xF, stack=+1),
    ddiv            = OP(0x6F, stack=-1),
    dload           = OP(0x18, stack=+1, base=U1Instruction),
    dload_0         = OP(0x26, stack=+1),
    dload_1         = OP(0x27, stack=+1),
    dload_2         = OP(0x28, stack=+1),
    dload_3         = OP(0x29, stack=+1),
    dmul            = OP(0x6B, stack=-1),
    dneg            = OP(0x77),
    drem            = OP(0x73, stack=-1),
    dreturn         = OP(0xAF),
    dstore          = OP(0x39, stack=-1, base=U1Instruction),
    dstore_0        = OP(0x47, stack=-1),
    dstore_1        = OP(0x48, stack=-1),
    dstore_2        = OP(0x49, stack=-1),
    dstore_3        = OP(0x4A, stack=-1),
    dsub            = OP(0x67, stack=-1),
    dup             = OP(0x59, stack=+1),
    dup_x1          = OP(0x5A, stack=+1),
    dup_x2          = OP(0x5B, stack=+1),
    dup2            = OP(0x5C, stack=+2),
    dup2_x1         = OP(0x5D, stack=+2),
    dup2_x2         = OP(0x5E, stack=+2),
    f2d             = OP(0x8D),
    f2i             = OP(0x8B),
    f2l             = OP(0x8C),
    fadd            = OP(0x62, stack=-1),
    faload          = OP(0x30, stack=-1),
    fastore         = OP(0x51, stack=-3),
    fcmpg           = OP(0x96, stack=-1),
    fcmpl           = OP(0x95, stack=-1),
    fconst_0        = OP(0xB, stack=+1),
    fconst_1        = OP(0xC, stack=+1),
    fconst_2        = OP(0xD, stack=+1),
    fdiv            = OP(0x6E, stack=-1),
    fload           = OP(0x17, stack=+1, base=U1Instruction),
    fload_0         = OP(0x22, stack=+1),
    fload_1         = OP(0x23, stack=+1),
    fload_2         = OP(0x24, stack=+1),
    fload_3         = OP(0x25, stack=+1),
    fmul            = OP(0x6A, stack=-1),
    fneg            = OP(0x76),
    frem            = OP(0x72, stack=-1),
    freturn         = OP(0xAE),
    fstore          = OP(0x38, stack=-1, base=U1Instruction),
    fstore_0        = OP(0x43, stack=-1),
    fstore_1        = OP(0x44, stack=-1),
    fstore_2        = OP(0x45, stack=-1),
    fstore_3        = OP(0x46, stack=-1),
    fsub            = OP(0x66, stack=-1),
    getfield        = OP(0xB4, arg_count=2),
    getstatic       = OP(0xB2, stack=+1, arg_count=2),
    goto            = OP(0xA7, arg_count=2),
    goto_w          = OP(0xC8, arg_count=4),
    i2b             = OP(0x91),
    i2c             = OP(0x92),
    i2d             = OP(0x87),
    i2f             = OP(0x86),
    i2l             = OP(0x85),
    i2s             = OP(0x93),
    iadd            = OP(0x60, stack=-1),
    iaload          = OP(0x2E, stack=-1),
    iand            = OP(0x7E, stack=-1),
    iastore         = OP(0x4F, stack=-3),
    iconst_m1       = OP(0x2, stack=+1),
    iconst_0        = OP(0x3, stack=+1),
    iconst_1        = OP(0x4, stack=+1),
    iconst_2        = OP(0x5, stack=+1),
    iconst_3        = OP(0x6, stack=+1),
    iconst_4        = OP(0x7, stack=+1),
    iconst_5        = OP(0x8, stack=+1),
    idiv            = OP(0x6C, stack=-1),
    if_acmpeq       = OP(0xA5, stack=-2, base=JumpBase),
    if_acmpne       = OP(0xA6, stack=-2, base=JumpBase),
    if_icmpeq       = OP(0x9F, stack=-2, base=JumpBase),
    if_icmpne       = OP(0xA0, stack=-2, base=JumpBase),
    if_icmplt       = OP(0xA1, stack=-2, base=JumpBase),
    if_icmpge       = OP(0xA2, stack=-2, base=JumpBase),
    if_icmpgt       = OP(0xA3, stack=-2, base=JumpBase),
    if_icmple       = OP(0xA4, stack=-2, base=JumpBase),
    ifeq            = OP(0x99, stack=-1, base=JumpBase),
    ifne            = OP(0x9A, stack=-1, base=JumpBase),
    iflt            = OP(0x9B, stack=-1, base=JumpBase),
    ifge            = OP(0x9C, stack=-1, base=JumpBase),
    ifgt            = OP(0x9D, stack=-1, base=JumpBase),
    ifle            = OP(0x9E, stack=-1, base=JumpBase),
    ifnonnull       = OP(0xC7, stack=-1, base=JumpBase),
    ifnull          = OP(0xC6, stack=-1, base=JumpBase),
    iinc            = OP(0x84, arg_count=2),
    iload           = OP(0x15, stack=+1, base=U1Instruction),
    iload_0         = OP(0x1A, stack=+1),
    iload_1         = OP(0x1B, stack=+1),
    iload_2         = OP(0x1C, stack=+1),
    iload_3         = OP(0x1D, stack=+1),
    imul            = OP(0x68, stack=-1),
    ineg            = OP(0x74),
    instanceof      = OP(0xC1, arg_count=2),
    invokedynamic   = OP(0xBA, stack=-1, arg_count=4),
    invokeinterface = OP(0xB9, stack=-1, arg_count=4),
    invokespecial   = OP(0xB7, stack=-1, arg_count=2),
    invokestatic    = OP(0xB8, stack=-1, base=InvokeU2Instruction),
    invokevirtual   = OP(0xB6, stack=-1, arg_count=2),
    ior             = OP(0x80, stack=-1),
    irem            = OP(0x70, stack=-1),
    ireturn         = OP(0xAC),
    ishl            = OP(0x78, stack=-1),
    ishr            = OP(0x7A, stack=-1),
    istore          = OP(0x36, stack=-1, base=U1Instruction),
    istore_0        = OP(0x3B, stack=-1),
    istore_1        = OP(0x3C, stack=-1),
    istore_2        = OP(0x3D, stack=-1),
    istore_3        = OP(0x3E, stack=-1),
    isub            = OP(0x64, stack=-1),
    iushr           = OP(0x7C, stack=-1),
    ixor            = OP(0x82, stack=-1),
    jsr             = OP(0xA8, stack=+1, arg_count=2),
    jsr_w           = OP(0xC9, stack=+1, arg_count=4),
    l2d             = OP(0x8A),
    l2f             = OP(0x89),
    l2i             = OP(0x88),
    ladd            = OP(0x61, stack=-1),
    laload          = OP(0x2F, stack=-1),
    land            = OP(0x7F, stack=-1),
    lastore         = OP(0x50, stack=-3),
    lcmp            = OP(0x94, stack=-1),
    lconst_0        = OP(0x9, stack=+1),
    lconst_1        = OP(0xA, stack=+1),
    ldc             = OP(0x12, stack=+1, base=LoadConstantInstruction),
    ldc_w           = OP(0x13, stack=+1, arg_count=2),
    ldc2_w          = OP(0x14, stack=+1, arg_count=2),
    ldiv            = OP(0x6D, stack=-1),
    lload           = OP(0x16, stack=+1, base=U1Instruction),
    lload_0         = OP(0x1E, stack=+1),
    lload_1         = OP(0x1F, stack=+1),
    lload_2         = OP(0x20, stack=+1),
    lload_3         = OP(0x21, stack=+1),
    lmul            = OP(0x69, stack=-1),
    lneg            = OP(0x75),
    lor             = OP(0x81, stack=-1),
    lrem            = OP(0x71, stack=-1),
    lreturn         = OP(0xAD),
    lshl            = OP(0x79, stack=-1),
    lshr            = OP(0x7B, stack=-1),
    lstore          = OP(0x37, stack=-1, base=U1Instruction),
    lstore_0        = OP(0x3F, stack=-1),
    lstore_1        = OP(0x40, stack=-1),
    lstore_2        = OP(0x41, stack=-1),
    lstore_3        = OP(0x42, stack=-1),
    lsub            = OP(0x65, stack=-1),
    lushr           = OP(0x7D, stack=-1),
    lxor            = OP(0x83, stack=-1),
    monitorenter    = OP(0xC2, stack=-1),
    monitorexit     = OP(0xC3, stack=-1),
    multianewarray  = OP(0xC5, arg_count=3),
    new             = OP(0xBB, stack=+1, arg_count=2),
    newarray        = OP(0xBC, base=U1Instruction),
    nop             = OP(0x0),
    pop             = OP(0x57, stack=-1),
    pop2            = OP(0x58, stack=-2),
    putfield        = OP(0xB5, stack=-2, arg_count=2),
    putstatic       = OP(0xB3, stack=-1, arg_count=2),
    ret             = OP(0xA9, base=U1Instruction),
    return_         = OP(0xB1, stack=+1),
    saload          = OP(0x35, stack=-1),
    sastore         = OP(0x56, stack=-3),
    sipush          = OP(0x11, stack=+1, arg_count=2),
    swap            = OP(0x5F),
    breakpoint      = OP(0xCA),
    impdep1         = OP(0xFE),
    impdep2         = OP(0xFF),
)

_InstructionCache = {}

# Patch up keyword those keywords.
OpTable["return"] = OpTable.pop("return_")

# Give us some bogies.
_InstructionCache["label"]   = Label

def get_instruction(name):
    name = name.rstrip("_")
    if name not in _InstructionCache:
        opcode, base, kw = OpTable[name]

        instruction = type(name, (base,), kw)
        instruction.opcode = opcode
        instruction.name = name

        _InstructionCache[name] = instruction

    return _InstructionCache[name]
