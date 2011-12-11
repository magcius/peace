
from peace import assembler, classfile, constants

def assemble(asm):
    const = constants.ConstantPool()
    asm.write_constants(const)

    asm.pass1()
    return const, asm.serialize()

def test_nothing_function():
    asm = assembler.CodeAssembler([])
    asm.emit('return')

    _, bytes = assemble(asm)
    assert bytes == '\xB1'

def test_cpool():
    asm = assembler.CodeAssembler([])
    iinfo = constants.IntegerInfo(22)
    asm.emit('ldc', iinfo)
    asm.emit('istore_0')

    cpool, bytes = assemble(asm)
    assert cpool.value_at(0) == iinfo

    assert bytes == '\x12\x00\x3B'
