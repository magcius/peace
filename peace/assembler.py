
from cStringIO import StringIO
import struct

from peace import util
from peace.instructions import get_instruction

class Label(object):
    def __init__(self, name):
        self.name = name
        self.address = None
        self.stack_depth, self.scope_depth = 0, 0

    def __repr__(self):
        return "<Label (name=%s, stack_depth=%d, scope_depth=%d)>" \
            % (self.name, self.stack_depth, self.scope_depth)

class CodeAssembler(object):
    def __init__(self, locals):
        self.instructions = []
        self.locals = util.ValuePool()

        self.flags = 0
        self._stack_depth = 0
        self.max_stack_depth = 0
        self.max_local_count = 0

        for local in locals:
            self.set_local(local)

        # jump-like instructions
        self.jumps = []

        # name -> Label
        self.labels  = {}

    def make_label(self, name):
        label = Label(name)
        label.stack_depth = self.stack_depth
        return self.labels.setdefault(name, label)

    def emit(self, name, *a, **kw):
        self.add_instruction(get_instruction(name)(*a, **kw))

    def add_instruction(self, instruction):
        self.instructions.append(instruction)
        instruction.assembler_added(self)
        return instruction

    def get_stack_depth(self):
        return self._stack_depth

    def set_stack_depth(self, value):
        self._stack_depth = value
        if value > self.max_stack_depth:
            self.max_stack_depth = value
    stack_depth = property(get_stack_depth, set_stack_depth)

    @property
    def next_free_local(self):
        return self.locals.next_free()

    def set_local(self, name):
        index = self.locals.index_for(name)
        if self.local_count > self.max_local_count:
            self.max_local_count = self.local_count
        return index

    def get_local(self, name):
        return self.locals.get_index(name)

    def kill_local(self, name):
        index = self.locals.kill(name)
        if self.local_count > self.max_local_count:
            self.max_local_count = self.local_count
        return index

    def has_local(self, name):
        return name in self.locals

    @property
    def local_count(self):
        return len(self.locals)

    def pass1(self):
        for inst in self.instructions:
            inst.assembler_pass1(self)

    def write_constants(self, pool):
        for inst in self.instructions:
            inst.write_constants(pool)

    def serialize(self):
        code = StringIO()
        for inst in self.instructions:
            inst.assembler_pass2(self, code.tell())
            code.write(inst.serialize())

        # Patch up jumps.
        for inst in self.jumps:
            assert inst in self.instructions
            code.seek(inst.address+1)
            patch = struct.pack('<H', inst.label.address - (inst.address+3))
            code.write(patch)

        return code.getvalue()
