
from peace.lexer import Lexer
from peace.parser import Parser
from peace.codegen import CodeGenerator

def compile_me(source, classname):
    tokens = list(Lexer(source))

    parser = Parser(tokens)
    suite = parser.toplevel()

    codegen = CodeGenerator(classname, "java/lang/Object", suite)
    codegen.compile()
    with open('%s.class' % (classname,), 'wb') as f:
        f.write(codegen.serialize())

def main():
    import sys
    with open(sys.argv[1], 'r') as f:
        compile_me(f.read(), sys.argv[2])

if __name__ == '__main__':
    main()

