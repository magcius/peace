
class empty(object):
    def __repr__(self):
        return "(empty)"

empty = empty()

class reserved(object):
    def __repr__(self):
        return "(reserved)"

reserved = reserved()

class ValuePool(object):
    write_method_name = None

    def __init__(self):
        self.index_map = {}
        self.pool = []
        self.free = []

    def __contains__(self, value):
        return value in self.index_map

    def __iter__(self):
        return iter(self.pool)

    def __str__(self):
        return "ConstantPool(%r)" % (self.pool,)

    def __len__(self):
        return len(self.pool)

    def merge(self, pool):
        for value in pool:
            self.index_for(value)

    def get_index(self, value):
        return self.index_map[value]

    def add_value(self, value):
        index, reuse = self.next_free()

        if reuse:
            self.pool[index] = value
        else:
            self.pool.append(value)

        self.index_map.setdefault(value, index)

        return index

    def index_for(self, value):
        if self.write_method_name:
            m = getattr(value, self.write_method_name, None)
            if m is not None:
                value.write_constants(self)

        if value in self.index_map:
            return self.index_map[value]

        return self.add_value(value)

    def value_at(self, index):
        try:
            value = self.pool[index]
        except IndexError:
            raise ValueError("No value at %d." % (index,))

        if value is empty:
            raise ValueError("No value at %d." % (index,))

        return value

    def next_free(self):
        if self.free:
            index = self.free.pop(0)
            reuse = True
        else:
            index = len(self.pool)
            reuse = False

        return index, reuse

    def kill(self, value):
        index = self.index_map[value]
        del self.index_map[value]
        self.pool[index] = empty
        self.free.append(index)
        return index
