# encoding: utf8

# lifted from wikipedia
OpTable = """
aaload | 32 || || arrayref, index → value
aastore  | 53 || || arrayref, index, value →
aconst_null | 01 || || → null
aload | 19 || 1: index || → objectref
aload_0 | 2a || || → objectref
aload_1 | 2b || || → objectref
aload_2 | 2c || || → objectref
aload_3 | 2d || || → objectref
anewarray | bd || 2: indexbyte1, indexbyte2 || count → arrayref
arraylength | be || || arrayref → length
astore | 3a || 1: index || objectref →
astore_0 | 4b || || objectref →
astore_1 | 4c || || objectref →
astore_2 | 4d || || objectref →
astore_3 | 4e || || objectref →
athrow | bf || || objectref → [empty], objectref
baload | 33 || || arrayref, index → value
bastore | 54 || || arrayref, index, value →
bipush | 10 || 1: byte || → value
caload | 34 || || arrayref, index → value
castore | 55 || || arrayref, index, value →
checkcast | c0 || 2: indexbyte1, indexbyte2 || objectref → objectref
d2f | 90 || || value → result
d2i | 8e || || value → result
d2l | 8f || || value → result
dadd | 63 || || value1, value2 → result
daload | 31 || || arrayref, index → value
dastore | 52 || || arrayref, index, value →
dcmpg | 98 || || value1, value2 → result
dcmpl | 97 || || value1, value2 → result
dconst_0 | 0e || || → 0.0
dconst_1 | 0f || || → 1.0
ddiv | 6f || || value1, value2 → result
dload | 18 || 1: index || → value
dload_0 | 26 || || → value
dload_1 | 27 || || → value
dload_2 | 28 || || → value
dload_3 | 29 || || → value
dmul | 6b || || value1, value2 → result
dneg | 77 || || value → result
drem | 73 || || value1, value2 → result
dreturn | af || || value → [empty]
dstore | 39 || 1: index || value →
dstore_0 | 47 || || value →
dstore_1 | 48 || || value →
dstore_2 | 49 || || value →
dstore_3 | 4a || || value →
dsub | 67 || || value1, value2 → result
dup | 59 || || value → value, value
dup_x1 | 5a || || value2, value1 → value1, value2, value1
dup_x2 | 5b || || value3, value2, value1 → value1, value3, value2, value1
dup2 | 5c || || {value2, value1} → {value2, value1}, {value2, value1}
dup2_x1 | 5d || || value3, {value2, value1} → {value2, value1}, value3, {value2, value1}
dup2_x2 | 5e || || {value4, value3}, {value2, value1} → {value2, value1}, {value4, value3}, {value2, value1}
f2d | 8d || || value → result
f2i | 8b || || value → result
f2l | 8c || || value → result
fadd | 62 || || value1, value2 → result
faload | 30 || || arrayref, index → value
fastore | 51 || || arrayref, index, value →
fcmpg | 96 || || value1, value2 → result
fcmpl | 95 || || value1, value2 → result
fconst_0 | 0b || || → 0.0f
fconst_1 | 0c || || → 1.0f
fconst_2 | 0d || || → 2.0f
fdiv | 6e || || value1, value2 → result
fload | 17 || 1: index || → value
fload_0 | 22 || || → value
fload_1 | 23 || || → value
fload_2 | 24 || || → value
fload_3 | 25 || || → value
fmul | 6a || || value1, value2 → result
fneg | 76 || || value → result
frem | 72 || || value1, value2 → result
freturn | ae || || value → [empty]
fstore | 38 || 1: index || value →
fstore_0 | 43 || || value →
fstore_1 | 44 || || value →
fstore_2 | 45 || || value →
fstore_3 | 46 || || value →
fsub | 66 || || value1, value2 → result
getfield | b4 || 2: index1, index2 || objectref → value
getstatic | b2 || 2: index1, index2 || → value
goto | a7 || 2: branchbyte1, branchbyte2 || [no change]
goto_w | c8 || 4: branchbyte1, branchbyte2, branchbyte3, branchbyte4 || [no change]
i2b | 91 || || value → result
i2c | 92 || || value → result
i2d | 87 || || value → result
i2f | 86 || || value → result
i2l | 85 || || value → result
i2s | 93 || || value → result
iadd | 60 || || value1, value2 → result
iaload | 2e || || arrayref, index → value
iand | 7e || || value1, value2 → result
iastore | 4f || || arrayref, index, value →
iconst_m1 | 02 || || → -1
iconst_0 | 03 || || → 0
iconst_1 | 04 || || → 1
iconst_2 | 05 || || → 2
iconst_3 | 06 || || → 3
iconst_4 | 07 || || → 4
iconst_5 | 08 || || → 5
idiv | 6c || || value1, value2 → result
if_acmpeq | a5 || 2: branchbyte1, branchbyte2 || value1, value2 →
if_acmpne | a6 || 2: branchbyte1, branchbyte2 || value1, value2 →
if_icmpeq | 9f || 2: branchbyte1, branchbyte2 || value1, value2 →
if_icmpne | a0 || 2: branchbyte1, branchbyte2 || value1, value2 →
if_icmplt | a1 || 2: branchbyte1, branchbyte2 || value1, value2 →
if_icmpge | a2 || 2: branchbyte1, branchbyte2 || value1, value2 →
if_icmpgt | a3 || 2: branchbyte1, branchbyte2 || value1, value2 →
if_icmple | a4 || 2: branchbyte1, branchbyte2 || value1, value2 →
ifeq | 99 || 2: branchbyte1, branchbyte2 || value →
ifne | 9a || 2: branchbyte1, branchbyte2 || value →
iflt | 9b || 2: branchbyte1, branchbyte2 || value →
ifge | 9c || 2: branchbyte1, branchbyte2 || value →
ifgt | 9d || 2: branchbyte1, branchbyte2 || value →
ifle | 9e || 2: branchbyte1, branchbyte2 || value →
ifnonnull | c7 || 2: branchbyte1, branchbyte2 || value →
ifnull | c6 || 2: branchbyte1, branchbyte2 || value →
iinc | 84 || 2: index, const || [no change]
iload | 15 || 1: index || → value
iload_0 | 1a || || → value
iload_1 | 1b || || → value
iload_2 | 1c || || → value
iload_3 | 1d || || → value
imul | 68 || || value1, value2 → result
ineg | 74 || || value → result
instanceof | c1 || 2: indexbyte1, indexbyte2 || objectref → result
invokedynamic | ba || 4: indexbyte1, indexbyte2, 0, 0 || ... →
invokeinterface | b9 || 4: indexbyte1, indexbyte2, count, 0 || objectref ... →
invokespecial | b7 || 2: indexbyte1, indexbyte2 || objectref ... →
invokestatic | b8 || 2: indexbyte1, indexbyte2 || ... →
invokevirtual | b6 || 2: indexbyte1, indexbyte2 || objectref ... →
ior | 80 || || value1, value2 → result
irem | 70 || || value1, value2 → result
ireturn | ac || || value → [empty]
ishl | 78 || || value1, value2 → result
ishr | 7a || || value1, value2 → result
istore | 36 || 1: index || value →
istore_0 | 3b || || value →
istore_1 | 3c || || value →
istore_2 | 3d || || value →
istore_3 | 3e || || value →
isub | 64 || || value1, value2 → result
iushr | 7c || || value1, value2 → result
ixor | 82 || || value1, value2 → result
jsr | a8 || 2: branchbyte1, branchbyte2 || → address
jsr_w | c9 || 4: branchbyte1, branchbyte2, branchbyte3, branchbyte4 || → address
l2d | 8a || || value → result
l2f | 89 || || value → result
l2i | 88 || || value → result
ladd | 61 || || value1, value2 → result
laload | 2f || || arrayref, index → value
land | 7f || || value1, value2 → result
lastore | 50 || || arrayref, index, value →
lcmp | 94 || || value1, value2 → result
lconst_0 | 09 || || → 0L
lconst_1 | 0a || || → 1L
ldc | 12 || 1: index || → value
ldc_w | 13 || 2: indexbyte1, indexbyte2 || → value
ldc2_w | 14 || 2: indexbyte1, indexbyte2 || → value
ldiv | 6d || || value1, value2 → result
lload | 16 || 1: index || → value
lload_0 | 1e || || → value
lload_1 | 1f || || → value
lload_2 | 20 || || → value
lload_3 | 21 || || → value
lmul | 69 || || value1, value2 → result
lneg | 75 || || value → result
lor | 81 || || value1, value2 → result
lrem | 71 || || value1, value2 → result
lreturn | ad || || value → [empty]
lshl | 79 || || value1, value2 → result
lshr | 7b || || value1, value2 → result
lstore | 37 || 1: index || value →
lstore_0 | 3f || || value →
lstore_1 | 40 || || value →
lstore_2 | 41 || || value →
lstore_3 | 42 || || value →
lsub | 65 || || value1, value2 → result
lushr | 7d || || value1, value2 → result
lxor | 83 || || value1, value2 → result
monitorenter | c2 || || objectref →
monitorexit | c3 || || objectref →
multianewarray | c5 || 3: indexbyte1, indexbyte2, dimensions || count1 ... → arrayref
new | bb || 2: indexbyte1, indexbyte2 || → objectref
newarray | bc || 1: atype || count → arrayref
nop | 00 || || [No change]
pop | 57 || || value →
pop2 | 58 || || {value2, value1} →
putfield | b5 || 2: indexbyte1, indexbyte2 || objectref, value →
putstatic | b3 || 2: indexbyte1, indexbyte2 || value →
ret | a9 || 1: index || [no change]
return | b1 || || → [empty]
saload | 35 || || arrayref, index → value
sastore | 56 || || arrayref, index, value →
sipush | 11 || 2: byte1, byte2 || → value
swap | 5f || || value2, value1 → value1, value2
breakpoint | ca || ||
impdep1 | fe || ||
impdep2 | ff || ||
""".strip()

print "OpTable = dict("

extra = []

for line in OpTable.splitlines():
    name_and_opcode, extra_bytes, stack = line.split("||")
    name, opcode = name_and_opcode.strip().split(" | ")
    opcode = int(opcode, 16)

    extra_bytes = extra_bytes.strip()
    if not extra_bytes:
        extra_bytes_count = 0
    else:
        extra_bytes_count = int(extra_bytes.split(":")[0], 10)

    if not stack.strip() or "no change" in stack.strip().lower():
        stack_change = 0
    else:
        left, right = stack.split("→")
        if not left.strip():
            left_change = 0
        else:
            left_change = len(left.split(','))

        if not right.strip():
            right_change = 0
        else:
            right_change = len(right.split(','))

        stack_change = right_change - left_change
        if '...'in stack:
            extra.append(name)

    print "    %s = OP(0x%X," % (name, opcode),

    if stack_change:
        stack_change_str = ("+%d" % (stack_change,) if stack_change > 0 else str(stack_change))
        print "stack=%s," % (stack_change_str,),

    if extra_bytes_count:
        print "arg_count=%d," % (extra_bytes_count,),

    print "),"

print ")"

