
import re
import string

class Token(object):
    def __init__(self, kind, contents):
        self.kind = kind
        self.contents = contents

    def __repr__(self):
        return 'Token(%r, %r)' % (self.kind, self.contents)

# tokens are ordered by length, so that
# it will try the longer tokens before the shorter ones
BASIC_TOKENS = [
    (2, { '==': 'CMP_EQUALS',
          '&&': 'AND',
          '||': 'OR', }),
    (1, { '{': 'OPEN_BLOCK',
          '}': 'CLOSE_BLOCK',
          '(': 'OPEN_PAREN',
          ')': 'CLOSE_PAREN',
          ',': 'COMMA',
          ';': 'SEMICOLON',
          '=': 'EQUALS', }),
]

VALID_ID = re.compile('[a-zA-Z$_][a-zA-Z0-9$_]*$')
NOT_PART_OF_IDENT = set(string.letters + string.digits + '_$')
KEYWORDS = 'function', 'if', 'var'

STRING_ESCAPES = {
    'r': '\r',
    'n': '\n',
    't': '\t'
}

class Lexer(object):
    def __init__(self, stream):
        self.current = 0
        self.stream = stream

    def chew(self):
        v = self.stream[self.current]
        self.current += 1
        return v

    def unchew(self):
        self.current -= 1

    def peek(self):
        return self.stream[self.current]

    def peek_string(self, amount=1, first_char_chewed=True):
        offset = -1 if first_char_chewed else 0
        return self.stream[self.current+offset:self.current+offset+amount]

    def try_keyword(self, keyword, first_char_chewed=True):
        offset = -1 if first_char_chewed else 0
        got = self.stream[self.current+offset:self.current+offset+len(keyword)]
        if got == keyword:
            after_char = self.stream[self.current+offset+len(keyword)]

            # If the user types "functionMyFoo", we need to make
            # sure that we don't erroneously return a keyword here
            if after_char not in NOT_PART_OF_IDENT:
                self.current += len(keyword)
                return True

        return False

    def __iter__(self):
        return self

    def string_escape(self):
        # backslash is chewed
        char = self.chew()
        if char in STRING_ESCAPES:
            return STRING_ESCAPES[char]

        if char == 'x':
            chars = ''.join((self.chew(), self.chew()))
            return chr(int(chars, 16))

        if char in ('\\', '"', '\''):
            return char

        raise SyntaxError

    def string_literal(self, delim):
        # starting delim is chewed up
        cache = ''
        while True:
            try:
                char = self.chew()
            except IndexError:
                raise SyntaxError

            if char == delim:
                return cache

            if char == '\\':
                cache += self.string_escape()
            else:
                cache += char

    def identifier(self, start):
        cache = start
        while True:
            try:
                char = self.chew()
            except IndexError:
                return cache

            cache += char

            if not VALID_ID.match(cache):
                # put back the last token that didn't match
                # and strip it from the results
                self.unchew()
                return cache[:-1]

    def number(self, start):
        cache = start
        while True:
            try:
                char = self.chew()
            except IndexError:
                return cache

            cache += char

            # XXX - handle fractional numbers another day
            if char not in string.digits:
                self.unchew()
                return int(cache[:-1], 10)

    def next(self, ignore_whitespace=True):
        while True:
            try:
                char = self.chew()
            except IndexError:
                raise StopIteration

            if ignore_whitespace and char in ' \r\n\t':
                continue

            elif char in string.digits:
                return Token(intern('NUMBER'), self.number(char))

            elif char in ('"', '\''):
                return Token(intern('STRING'), self.string_literal(char))

            for length, tokens in BASIC_TOKENS:
                lexeme = self.peek_string(length)
                if lexeme in tokens:
                    self.current += length - 1
                    return Token(intern(tokens[lexeme]), lexeme)

            for keyword in KEYWORDS:
                if self.try_keyword(keyword):
                    return Token(intern(keyword.upper()), keyword)

            return Token(intern('IDENTIFIER'), self.identifier(char))

if __name__ == '__main__':
    l = Lexer("""
function foobar(foo bar, eggs spam){==}
""")
    print list(l)
