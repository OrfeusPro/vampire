"""Bounded live-memory policy and guarded allocation ownership for lifecycle proof."""


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
                raise ValueError('Lifecycle memory range differs')
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
        self.fixture_writes = []
        self.initializing_owner = False

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
            raise ValueError('Lifecycle read of retired allocation')
        if native and not self.contained(address, size, self.native_read_windows):
            raise ValueError('Lifecycle native read outside declared live windows')

    def writable(self, address, size, *, native=False):
        if size == 0:
            return
        if size < 0 or self.overlaps(address, size, self.readonly + self.retired):
            raise ValueError('Lifecycle write to immutable or retired allocation')
        if native and not self.contained(address, size, self.native_windows):
            raise ValueError('Lifecycle native write outside declared windows')
        if self.fixture_windows is not None and not self.contained(address, size, self.fixture_windows):
            raise ValueError('Lifecycle fixture write outside declared windows')

    def mem_read(self, address, size):
        self.readable(address, size)
        return self.native.mem_read(address, size)

    def mem_write(self, address, data):
        self.writable(address, len(data))
        if self.fixture_windows is not None and not self.initializing_owner:
            self.fixture_writes.append((address, len(data)))
        return self.native.mem_write(address, data)

    def snapshot(self, address, size):
        return bytes(self.native.mem_read(address, size))


class Ledger:
    """Typed guarded owners; retirement preserves a host-only final snapshot."""
    def __init__(self, memory, start, end, poison, static_reads=(), static_writes=()):
        self.memory, self.cursor, self.end, self.poison = memory, start, end, poison
        self.static_reads, self.static_writes = list(static_reads), list(static_writes)
        self.records, self.by_name = {}, {}
        self.refresh()

    def refresh(self):
        live = [(at, row['size']) for at, row in self.records.items() if not row['retired']]
        self.memory.native_read_allow(self.static_reads + live)
        self.memory.native_allow(self.static_writes + live)

    def allocate(self, size, kind, name, *, fixture=False):
        if type(size) is not int or not 1 <= size <= 8192 or name in self.by_name:
            raise ValueError('Lifecycle allocation size/name differs')
        address = (self.cursor + 31) & ~15
        if address + size + 16 > self.end:
            raise ValueError('Lifecycle bounded heap exhausted')
        self.cursor = address + size + 48
        if fixture:
            self.memory.begin_fixture([(address - 16, size + 32)])
        self.memory.initializing_owner = True
        try:
            self.memory.mem_write(address - 16, b'\xa5' * 16 + bytes([self.poison]) * size + b'\xa6' * 16)
        finally:
            self.memory.initializing_owner = False
            if fixture:
                self.memory.end_fixture()
        self.records[address] = dict(size=size, kind=kind, name=name, retired=False)
        self.by_name[name] = address
        self.refresh()
        return address

    def record(self, address, size=None, kind=None):
        row = self.records.get(address)
        if (row is None or row['retired'] or size is not None and row['size'] != size
                or kind is not None and row['kind'] != kind):
            raise ValueError('Lifecycle owner is foreign, retired, wrong-sized or wrong-kind')
        return row

    def owner(self, address, size=1):
        for at, row in self.records.items():
            if not row['retired'] and at <= address and address + size <= at + row['size']:
                return at, row
        raise ValueError('Lifecycle span has no live typed owner')

    def name(self, address):
        if not address:
            return None
        row = self.records.get(address)
        if row:
            return row['name']
        for at, row in self.records.items():
            if at <= address < at + row['size']:
                return row['name'] + '+' + hex(address - at)
        raise ValueError('Lifecycle symbolic address has no owner')

    def check_guards(self):
        for at, row in self.records.items():
            if (self.memory.snapshot(at - 16, 16) != b'\xa5' * 16
                    or self.memory.snapshot(at + row['size'], 16) != b'\xa6' * 16):
                raise ValueError('Lifecycle allocation guard changed')

    def release(self, address, *, size=None, kind=None):
        row = self.record(address, size, kind)
        self.check_guards()
        row['snapshot'] = self.memory.snapshot(address, row['size'])
        row['retired'] = True
        self.memory.retire(address, row['size'])
        self.refresh()
        return row

    def bytes(self, address):
        row = self.records[address]
        return row['snapshot'] if row['retired'] else self.memory.snapshot(address, row['size'])


def verify_preserved(ledger, before, writes, poison):
    """Unknown owner bytes survive unless source/scoped provider actually wrote."""
    for address, row in ledger.records.items():
        initial = before.get(address, bytes([poison]) * row['size'])
        final = ledger.bytes(address)
        if not all(old == new for index,(old,new) in enumerate(zip(initial, final))
                if not any(start <= address+index < start+size for start,size in writes)):
            raise ValueError('Lifecycle unknown owner bytes changed outside source/scoped provider writes')


def verify_live_owners(ledger, retained_names, descendants, fixture_names):
    live = {row['name']:row for row in ledger.records.values() if not row['retired']}
    if set(live) != set(retained_names) | set(descendants) | set(fixture_names):
        raise ValueError('Lifecycle live-owner audit found a leaked or missing typed owner')
    for name in descendants:
        if live[name]['kind'] != 'sentinel' or live[name]['size'] != 16:
            raise ValueError('Lifecycle retained backend descendant ownership differs')
    for name,kind in fixture_names.items():
        if live[name]['kind'] != kind:
            raise ValueError('Lifecycle retained fixture owner kind differs')
