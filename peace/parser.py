
from peace.classfile import ACC_STATIC, ACC_PUBLIC

class Suite(object):
    def __init__(self, functions):
        self.functions = functions

    def compile(self, compiler, context):
        for f in self.functions:
            f.compile(compiler, context)

class FunctionDefinition(object):
    def __init__(self, name, paramspec, body):
        self.name = name
        self.paramspec = paramspec
        self.body = body

    def compile(self, compiler, context):
        # TODO - generate real descriptors
        name = self.name.contents
        DESCRIPTORS = {
            "main": "([Ljava/lang/String;)V"
        }

        param_names = [t.contents for t in self.paramspec]
        compiler.begin_method(name, DESCRIPTORS[name], param_names, ACC_STATIC | ACC_PUBLIC)

        self.body.compile(compiler, context)
        compiler.exit_current_rib()

class Block(object):
    def __init__(self, statements):
        self.statements = statements

    def compile(self, compiler, context):
        for s in self.statements:
            s.compile(compiler, context)

class VarDeclaration(object):
    def __init__(self, var_name, value):
        self.var_name = var_name
        self.value = value

class Load(object):
    def __init__(self, expression):
        self.expression = expression

class IfStatement(object):
    def __init__(self, expression, body):
        self.expression = expression
        self.body = body

class FunctionCall(object):
    def __init__(self, calling, arglist):
        self.calling = calling
        self.arglist = arglist

class BinaryExpression(object):
    def __init__(self, op, lhs, rhs):
        self.op = op
        self.lhs = lhs
        self.rhs = rhs

class Parser(object):
    def __init__(self, tokens):
        self.current = 0
        self.tokens = tokens

    def has_next(self):
        return self.current < len(self.tokens)

    def chew(self):
        v = self.tokens[self.current]
        self.current += 1
        return v

    def unchew(self):
        self.current -= 1
    
    def peek(self):
        return self.tokens[self.current]

    def expects_any(self, kinds):
        got = self.chew()
        if got.kind not in kinds:
            raise SyntaxError
        return got

    def expects(self, kind):
        return self.expects_any((kind,))

    def hd(self):
        return self.peek().kind


    def toplevel(self):
        while self.has_next():
            base = self.chew()
            functions = []
            if base.kind == 'FUNCTION':
                functions.append(self.function())
        return Suite(functions)

    def function(self):
        # "FUNCTION" token already chewed up
        name = self.expects('IDENTIFIER')

        self.expects('OPEN_PAREN')
        paramspec = self.paramspec()
        self.expects('CLOSE_PAREN')

        self.expects('OPEN_BLOCK')
        block = self.block()

        return FunctionDefinition(name, paramspec, block)

    def paramspec(self):
        paramspec = []
        while self.hd() != 'CLOSE_PAREN':
            paramspec.append(self.expects('IDENTIFIER').contents)
            if not self.hd() == 'COMMA':
                break
        return paramspec

    def block(self):
        # "OPEN_BLOCK" token already chewed up
        statements = []
        while self.hd() != 'CLOSE_BLOCK':
            statements.append(self.statement())
        self.chew() # CLOSE_BLOCK
        return Block(statements)

    def statement(self):
        chewed = self.chew()

        if chewed.kind == 'IF':
            statement = self.if_statement()
        elif chewed.kind == 'OPEN_BLOCK':
            statement = self.block()
        elif chewed.kind == 'VAR':
            statement = self.var_declaration()
            self.expects('SEMICOLON')
        else:
            self.unchew()
            statement = self.logical_or_expression()
            self.expects('SEMICOLON')

        return statement

    def var_declaration(self):
        # "VAR" token is already chewed
        var_name = self.expects('IDENTIFIER')
        self.expects('EQUALS')
        value = self.value()
        return VarDeclaration(var_name, value)

    def base_expression(self):
        lhs = self.value()
        if self.hd() == 'OPEN_PAREN':
            return self.function_call(lhs)
        return Load(lhs)

    def equality_expression(self):
        lhs = self.base_expression()
        while self.hd() in ('CMP_EQUALS',):
            kind = self.chew()
            lhs = BinaryExpression(kind, lhs, self.base_expression())
        return lhs

    def logical_and_expression(self):
        lhs = self.equality_expression()
        while self.hd() == 'AND':
            self.chew()
            lhs = BinaryExpression('AND', lhs, self.equality_expression())
        return lhs

    def logical_or_expression(self):
        lhs = self.logical_and_expression()
        while self.hd() == 'OR':
            self.chew()
            lhs = BinaryExpression('OR', lhs, self.logical_and_expression())
        return lhs

    def if_statement(self):
        # "IF" token already chewed
        self.expects('OPEN_PAREN')
        expression = self.logical_or_expression()
        self.expects('CLOSE_PAREN')
        body = self.statement()
        return IfStatement(expression, body)

    def function_call(self, calling):
        self.expects('OPEN_PAREN')
        arglist = self.arglist()
        self.expects('CLOSE_PAREN')
        return FunctionCall(calling, arglist)

    def arglist(self):
        arglist = []
        while self.hd() != 'CLOSE_PAREN':
            arglist.append(self.value())
            if self.hd() != 'COMMA':
                break

        return arglist

    def value(self):
        # TODO - full expressions
        return self.expects_any(('STRING', 'IDENTIFIER', 'NUMBER'))
