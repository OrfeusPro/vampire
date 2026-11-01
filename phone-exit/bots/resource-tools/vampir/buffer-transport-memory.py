"""Bounded live-memory policy and guarded allocation ownership for buffer proof."""


class MemoryPolicy:
    def __init__(self, native):
        self.native = native
        self.reset()

    def __getattr__(self, name):
        return getattr(self.native, name)

    @staticmethod
    def ranges(values):
        result = []
        for address, size in values:
            if type(address) is not int or type(size) is not int or address < 0 or size <= 0:
                raise ValueError('Buffer memory range differs')
            result.append((address, address + size))
        return result

    @staticmethod
    def overlaps(address, size, ranges):
        return any(address < end and address + size > start for start, end in ranges)

    @staticmethod
    def contained(address, size, ranges):
        return any(start <= address and address + size <= end for start, end in ranges)

    def reset(self):
        self.readonly, self.retired, self.native_windows = [], [], []
        self.native_read_windows = []
        self.fixture_windows = None

    def protect(self, values):
        self.readonly.extend(self.ranges(values))

    def retire(self, address, size):
        self.retired.extend(self.ranges([(address, size)]))

    def native_allow(self, values):
        self.native_windows = self.ranges(values)

    def native_extend(self, values):
        self.native_windows.extend(self.ranges(values))

    def native_read_allow(self, values):
        self.native_read_windows = self.ranges(values)

    def begin_fixture(self, values=()):
        if self.fixture_windows is not None:
            raise ValueError('Nested buffer fixture write scope')
        self.fixture_windows = self.ranges(values)

    def end_fixture(self):
        if self.fixture_windows is None:
            raise ValueError('Missing buffer fixture write scope')
        self.fixture_windows = None

    def readable(self, address, size, *, native=False):
        if size == 0:
            return
        if size < 0 or self.overlaps(address, size, self.retired):
            raise ValueError('Buffer read of retired allocation')
        if native and not self.contained(address, size, self.native_read_windows):
            raise ValueError('Buffer native read outside declared live windows')

    def writable(self, address, size, *, native=False):
        if size == 0:
            return
        if size < 0 or self.overlaps(address, size, self.readonly + self.retired):
            raise ValueError('Buffer write to immutable or retired allocation')
        if native and not self.contained(address, size, self.native_windows):
            raise ValueError('Buffer native write outside declared windows')
        if self.fixture_windows is not None and not self.contained(address, size, self.fixture_windows):
            raise ValueError('Buffer fixture write outside declared windows')

    def mem_read(self, address, size):
        self.readable(address, size)
        return self.native.mem_read(address, size)

    def mem_write(self, address, data):
        self.writable(address, len(data))
        return self.native.mem_write(address, data)

    def snapshot(self, address, size):
        return bytes(self.native.mem_read(address, size))


class AllocationLedger:
    """Provider raw blocks; native growth owns alignment header and vector fields."""
    MAXIMUM = 32768
    BEFORE, AFTER = b'\xa5' * 16, b'\xa6' * 16

    def __init__(self, memory, start, end, *, read_windows=()):
        self.memory, self.cursor, self.end = memory, start, end
        self.base_read_windows = list(read_windows)
        self.records = {}
        self.refresh_read_windows()

    def refresh_read_windows(self):
        values = list(self.base_read_windows)
        for address, row in self.records.items():
            if row['retired']:
                continue
            if row['owner'] == 'input':
                if row.get('read_size', 0):
                    values.append((address + row['read_offset'], row['read_size']))
            else:
                values.append((address, row['size']))
        self.memory.native_read_allow(values)

    def input_read_span(self, address, offset, size):
        row = self.records.get(address)
        if (row is None or row['retired'] or row['owner'] != 'input'
                or type(offset) is not int or type(size) is not int
                or offset < 0 or size < 0 or offset + size > row['size']):
            raise ValueError('Buffer input read span differs from its live owner')
        row.update(read_offset=offset, read_size=size)
        self.refresh_read_windows()

    def allocate(self, size, *, owner, fixture=False):
        if type(size) is not int or not 1 <= size <= self.MAXIMUM:
            raise ValueError('Buffer allocation request outside bounded provider')
        # Deliberately not 32-byte aligned: the native large-allocation branch
        # must perform its own alignment and retain the raw allocation pointer.
        address = ((self.cursor + 31) & ~31) + 17
        if address + size + 16 > self.end:
            raise ValueError('Buffer bounded heap exhausted')
        self.cursor = address + size + 48
        windows = [(address - 16, size + 32)]
        if fixture:
            self.memory.begin_fixture(windows)
        try:
            self.memory.mem_write(address - 16, self.BEFORE + b'\x5a' * size + self.AFTER)
        finally:
            if fixture:
                self.memory.end_fixture()
        self.records[address] = dict(size=size, owner=owner, retired=False)
        self.memory.native_extend([(address, size)])
        self.refresh_read_windows()
        return address

    def containing(self, address, size=0):
        for base, row in self.records.items():
            if not row['retired'] and base <= address and address + size <= base + row['size']:
                return base, row
        raise ValueError('Buffer span has no live allocation owner')

    def check_vector(self, begin, end, limit):
        if not 0 <= begin <= end <= limit:
            raise ValueError('Buffer retained vector descriptor ordering differs')
        capacity = limit - begin
        if not capacity:
            if begin or end or limit:
                raise ValueError('Buffer empty vector has a foreign pointer')
            return None
        raw, row = self.containing(begin, capacity)
        if row['owner'] != 'vector':
            raise ValueError('Buffer retained vector has a foreign allocation owner')
        if capacity >= 4096:
            delta = begin - raw
            if begin & 31 or not 8 <= delta <= 39 or row['size'] != capacity + 39:
                raise ValueError('Buffer retained aligned vector geometry/raw size differs')
            header = int.from_bytes(self.memory.mem_read(begin - 8, 8), 'little')
            if header != raw:
                raise ValueError('Buffer retained aligned vector raw-pointer header differs')
        elif begin != raw or row['size'] != capacity:
            raise ValueError('Buffer retained small vector pointer/raw size differs')
        return raw

    def check_guards(self):
        for address, row in self.records.items():
            if (self.memory.snapshot(address - 16, 16) != self.BEFORE
                    or self.memory.snapshot(address + row['size'], 16) != self.AFTER):
                raise ValueError('Buffer allocation guard changed')

    def release(self, address, size):
        row = self.records.get(address)
        if row is None or row['retired'] or row['size'] != size:
            raise ValueError('Buffer sized free is foreign, repeated or wrong-sized')
        self.check_guards()
        row['retired'] = True
        self.memory.retire(address, size)
        self.refresh_read_windows()


def copy_memory(memory, destination, source, size, *, move=False):
    if type(size) is not int or not 0 <= size <= AllocationLedger.MAXIMUM:
        raise ValueError('Buffer copy size outside fixture bound')
    if size and not move and destination < source + size and source < destination + size:
        raise ValueError('Buffer memcpy overlapping spans')
    memory.readable(source, size, native=True)
    memory.writable(destination, size)
    data = bytes(memory.mem_read(source, size)) if size else b''
    memory.begin_fixture([(destination, size)] if size else [])
    try:
        if size:
            memory.mem_write(destination, data)
    finally:
        memory.end_fixture()
    return destination


def fill_memory(memory, destination, fill, size):
    if type(size) is not int or not 0 <= size <= AllocationLedger.MAXIMUM:
        raise ValueError('Buffer fill size outside fixture bound')
    memory.writable(destination, size)
    memory.begin_fixture([(destination, size)] if size else [])
    try:
        if size:
            memory.mem_write(destination, bytes([fill & 255]) * size)
    finally:
        memory.end_fixture()
    return destination
