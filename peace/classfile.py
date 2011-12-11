
import struct

from peace import constants

class Code(object):
    def __init__(self, asm):
        self.attribute_name = constants.Utf8Info("Code")
        self.asm = asm

    def write_constants(self, pool):
        self._attribute_name_idx = pool.index_for(self.attribute_name)

    def serialize(self):
        code = self.asm.serialize()
        code_length = len(code)
        length = 2 + 2 + 4 + code_length + 2 + 2

        return struct.pack('>HIHHI',
                           self._attribute_name_idx,
                           length,
                           self.asm._max_stack_depth,
                           self.asm._max_local_count,
                           code_length) + code + '\0\0\0\0'

class MethodInfo(object):
    def __init__(self, name, descriptor, code, attributes=None, access=0):
        self.name = name
        self.name_utf8info = constants.Utf8Info(name)
        self.descriptor = descriptor
        self.descriptor_utf8info = constants.Utf8Info(descriptor)
        self.access = access

        self.code = code
        self.attributes = attributes or []
        self.attributes.append(code)

    def write_constants(self, pool):
        self._name_utf8_idx = pool.index_for(self.name_utf8info)
        self._descriptor_utf8_idx = pool.index_for(self.descriptor_utf8info)

    def serialize(self):
        bytes = struct.pack('>HHHH',
                            self.access,
                            self._name_utf8_idx,
                            self._descriptor_utf8_idx,
                            len(self.attributes))

        for attr in self.attributes:
            bytes += attr.serialize()
        return bytes

class CafeBabe(object):
    def __init__(self, name, methods):
        self.name = name
        self.cpool = constants.ConstantPool()
        self.class_info = constants.ClassInfo(self.name)
        self._class_info_idx = self.cpool.index_for(self.class_info)
        self.major, self.minor = 51, 0

        self.methods = methods
        for method in methods:
            method.write_constants(self.cpool)

    def serialize(self):
        bytes = 'cafebabe' + struct.pack('>HH', self.minor, self.major)
        bytes += self.cpool.serialize()
        bytes += struct.pack('>HHHHHH',
                             0, self._class_info_idx, 0,
                             0, 0, len(self.methods))
        for method in self.methods:
            bytes += method.serialize()
        bytes += struct.pack('>H', 0)
        return bytes