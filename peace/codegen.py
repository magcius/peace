
from peace import classfile, assembler

class Method(object):
    def __init__(self, name, params, rettype):
        self.name = name
        self.param_types, self.param_names = zip(*params) or ([], [])
        self.rettype = rettype

        self.asm = assembler.CodeAssembler(['this'] + list(self.param_names))

        self.method_info = classfile.MethodInfo(str(name), self.param_types, rettype,
                                                param_names=self.param_names)
        self.method_ = classfile.Code

class Context(object):
    def __init__(self, cafebabe):
        self.cafebabe = cafebabe

class Compiler(object):
    def __init__(self, suite):
        self.suite = suite
        self.cafebabe = classfile.CafeBabe()

    def compile(self):
        context = Context(self.cafebabe)
        self.suite.compile(context)

    def serialize(self):
        return self.cafebabe.serialize()
