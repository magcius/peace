
from peace import classfile, assembler

class MethodRib(object):
    def __init__(self, name, descriptor, param_names, access=0):
        self.name = name
        self.descriptor = descriptor

        self.asm = assembler.CodeAssembler(['this'] + param_names)

        self.code = classfile.Code(self.asm)
        self.method_info = classfile.MethodInfo(name, descriptor, self.code, access=access)

    def finalize(self, codegen):
        codegen.cafebabe.add_method(self.method_info)

class CodeGenerator(object):
    def __init__(self, name, superclass, suite):
        # Stack of old ribs.
        self.ribs = []
        # Current rib, not on rib stack.
        self.current_rib = None

        self.suite = suite
        self.cafebabe = classfile.CafeBabe(name, superclass)

    def enter_rib(self, rib):
        self.ribs.append(self.current_rib)
        self.current_rib = rib
        return rib

    def exit_current_rib(self):
        self.current_rib.finalize(self)
        self.current_rib = self.ribs.pop()

    def get_asm(self):
        return self.current_rib.asm
    asm = property(get_asm)

    def emit(self, name, *a, **kw):
        self.asm.emit(name, *a, **kw)

    def set_label(self, lblname):
        self.emit('label', lblname)

    def begin_method(self, name, descriptor, param_names, access=0):
        return self.enter_rib(MethodRib(name, descriptor, param_names, access))

    def compile(self):
        self.suite.compile(self, None)

    def serialize(self):
        return self.cafebabe.serialize()

if __name__ == '__main__':
    from peace.lexer import Lexer
    from peace.parser import Parser
    tokens = list(Lexer("""
function main() {
    print("Hello, world!");
}
"""))

    parser = Parser(tokens)
    suite = parser.toplevel()

    codegen = CodeGenerator("test", "java/lang/Object", suite)
    codegen.compile()
    with open('test.class', 'wb') as f:
        f.write(codegen.serialize())

