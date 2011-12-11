
import struct

from peace import util

class IntegerInfo(object):
    def __init__(self,  value):
        self.value = value

    def __hash__(self):
        return hash(('INTINFO', self.value))

    def serialize(self):
        return struct.pack('>BI', 3, self.value)

class Utf8Info(object):
    def __init__(self, utf8):
        self.utf8 = utf8

    def __hash__(self):
        return hash(('UTF8INFO', self.utf8))

    def serialize(self):
        return struct.pack('>BH', 1, len(self.utf8)) + self.utf8

class StringInfo(object):
    def __init__(self, string):
        self.string = string
        self.utf8info = Utf8Info(string)

    def __hash__(self):
        return hash(('STRINGINFO', self.string))

    def write_constants(self, pool):
        self._utf8_idx = pool.index_for(self.utf8info)

    def serialize(self):
        return struct.pack('>BH', 11, self._utf8_idx)

class ClassInfo(object):
    def __init__(self, name):
        self.name = name
        self.name_utf8info = Utf8Info(name)

    def write_constants(self, pool):
        self._name_utf8_idx = pool.index_for(self.name_utf8info)

    def serialize(self):
        return struct.pack('>BH', 7, self._name_utf8_idx)

class NameAndTypeInfo(object):
    def __init__(self, name, descriptor):
        self.name = name
        self.name_utf8info = Utf8Info(name)
        self.descriptor = descriptor
        self.descriptor_utf8info = Utf8Info(descriptor)

    def __repr__(self):
        return "NameAndTypeInfo(%r, %r)" % (self.name, self.descriptor)

    def write_constants(self, pool):
        self._name_utf8_idx = pool.index_for(self.name_utf8info)
        self._descriptor_utf8_idx = pool.index_for(self.descriptor_utf8info)

    def serialize(self):
        return struct.pack('>BHH', 12, self._name_utf8_idx, self._descriptor_utf8_idx)

class MethodrefInfo(object):
    def __init__(self, cls, nameandtype):
        self.cls = cls
        self.nameandtype = nameandtype

    def __repr__(self):
        return "MethodInfo(%r, %r)" % (self.nameandtype.name,
                                       self.nameandtype.descriptor)

    def write_constants(self, pool):
        self._cls_idx = pool.index_for(self.cls)
        self._nameandtype_idx = pool.index_for(self.nameandtype)

    def serialize(self):
        return struct.pack('>BHH', 10, self._cls_idx, self._nameandtype_idx)

class ConstantPool(util.ValuePool):
    write_method_name = "write_constants"
    def serialize(self):
        bytes = struct.pack('H', len(self))
        for item in self:
            bytes += item.serialize()
        return bytes
