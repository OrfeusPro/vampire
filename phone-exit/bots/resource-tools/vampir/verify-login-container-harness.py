"""Proof-bound Login container and name ownership; five whole roots and ID 4 leaf."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent



def runtime_inputs():
    import importlib.metadata
    result={}
    for name in ('capstone','unicorn'):
        found=[d for d in importlib.metadata.distributions(path=[str(HERE.parents[2]/'.tools/vampir-analysis')])
            if d.metadata['Name'].lower()==name]
        if len(found)!=1:raise ValueError('Missing or ambiguous native runtime')
        result[name]=dict(version=found[0].version,
            record_sha256=hashlib.sha256((found[0].read_text('RECORD') or '').encode()).hexdigest())
    return result


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module



class MemoryPolicy:
    """Enforce native write windows, immutable payloads and fixture-only mutations."""
    def __init__(self, native):
        self.native = native
        self.reset()

    def __getattr__(self, name): return getattr(self.native, name)

    @staticmethod
    def ranges(values):
        result = []
        for at, size in values:
            if type(at) is not int or type(size) is not int or at < 0 or size <= 0:
                raise ValueError('Container memory range differs')
            result.append((at, at+size))
        return result

    def reset(self):
        self.readonly, self.native_windows, self.retired = [], [], []
        self.fixture_windows = None

    def protect(self, values): self.readonly.extend(self.ranges(values))
    def native_allow(self, values): self.native_windows = self.ranges(values)
    def retire(self, at, size): self.retired.extend(self.ranges([(at, size)]))
    def begin_fixture(self, values=()):
        if self.fixture_windows is not None: raise ValueError('Nested container fixture write scope')
        self.fixture_windows = self.ranges(values)
    def end_fixture(self):
        if self.fixture_windows is None: raise ValueError('Missing container fixture write scope')
        self.fixture_windows = None

    @staticmethod
    def overlaps(at, size, ranges): return any(at < end and at+size > start for start, end in ranges)
    @staticmethod
    def contained(at, size, ranges): return any(start <= at and at+size <= end for start, end in ranges)

    def readable(self, at, size):
        if not size: return
        if size < 0 or self.overlaps(at, size, self.retired):
            raise ValueError('Container use after fixture free')

    def writable(self, at, size, *, native=False):
        if not size: return
        if size < 0 or self.overlaps(at, size, self.readonly+self.retired):
            raise ValueError('Container write to protected or retired memory')
        if native and not self.contained(at, size, self.native_windows):
            raise ValueError('Container native write outside mutable object/stack windows')
        if self.fixture_windows is not None and not self.contained(at, size, self.fixture_windows):
            raise ValueError('Container fixture write outside its explicit fields')

    def mem_read(self, at, size): self.readable(at, size); return self.native.mem_read(at, size)
    def mem_write(self, at, data): self.writable(at, len(data)); return self.native.mem_write(at, data)
    def snapshot(self, at, size): return bytes(self.native.mem_read(at, size))


def admit(context, root, functions, leaves, exports):
    if (context.get('family') != 'login-container' or context.get('format') != 'login-container-v1' or not context.get('transfer_proof')
            or any(k in context for k in ('function_budget', 'budget_scope', 'native_admission', 'native_input', 'native_handler'))
            or set(functions) != {int(at, 16) for at in context.get('functions', {}).values()}
            or len(functions) != 5 or leaves != {int(at, 16): data for at, data in context.get('leaves', {}).items()}
            or exports != context.get('exports') or not 1 <= len(exports) <= 8):
        raise ValueError('Login container root/export/leaf admission differs')
    index = load('container_index', HERE/'knowledge-index.py').api()
    adapter = load('container_adapter', HERE/'update-native-login-container.py').select('login-container')
    args = SimpleNamespace(root=Path(root), knowledge=HERE/'knowledge')
    args.source_store = load('container_sources', HERE/'update-bindings.py').SourceStore(index, args.root)
    if adapter.roots(context) != set(functions): raise ValueError('Login container executed roots differ')
    adapter.validate(index, args, context)
    native = load('container_native', HERE/'build-native-entry-code.py')
    bindings = load('container_bindings', HERE/'update-bindings.py')
    image = args.source_store.image(native, context['source_sha256'])
    adapter.export_coverage(args.root, context, native, bindings, image)
    args.source_store.validate()


def make_harness(context, exports, functions, leaves=None, root=None):
    import re
    SHA=context['source_sha256']
    if not isinstance(SHA,str) or not re.fullmatch('[0-9a-f]{64}',SHA):
        raise ValueError('Explicit full source SHA required')
    native = load('request_native', HERE/'build-native-entry-code.py')
    sys.path.insert(0, str(HERE.parents[2]/'.tools/vampir-analysis'))
    import unicorn
    from unicorn import x86_const as x
    if unicorn.__version__ != '2.1.4' or native.capstone.__version__ != '5.0.6':
        raise ValueError('Pinned request runtime required')
    root = Path(root) if root else native.ROOT
    source = root/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe'
    if Path(context['source']).resolve()!=source.resolve():
        raise ValueError('Context source path differs')
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA:
        raise ValueError('Request source SHA changed')
    image = native.Image(raw)
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    pages, allowed, found, evidence = set(), set(), set(), []
    h = SimpleNamespace(uc=uc, x=x, raw=raw, image=image, source=source, sha=SHA,
                        root=root, scratch=0x28000000, fixtures={}, fragments=[])

    def map_page(address):
        page = address & ~4095
        if page in pages:
            return
        uc.mem_map(page, 4096)
        pages.add(page)
        try:
            off = image.offset(page-image.pe.base)
        except ValueError:
            return
        uc.mem_write(page, raw[off:off+4096])

    def instruction(address, data):
        off = image.offset(address-image.pe.base)
        if raw[off:off+len(data)] != data:
            raise ValueError('Request instruction differs from source')
        decoded = list(decoder.disasm(data, address))
        if len(decoded) != 1 or decoded[0].size != len(data):
            raise ValueError('Request instruction boundary differs')
        allowed.add(address)
        map_page(address)
        map_page(address+len(data)-1)
        for operand in decoded[0].operands:
            if operand.type == native.X86_OP_MEM and operand.mem.base == native.X86_REG_RIP:
                target = address+len(data)+operand.mem.disp
                map_page(target)
                map_page(target+511)

    # A checked container proof owns these five whole roots and the ID leaf.
    admit(context, root, set(functions), leaves or {}, exports)
    for run, expected in exports.items():
        path = root/'ghidra/request-exports'/SHA/run/'details.json'
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != expected:
            raise ValueError('Request export SHA changed')
        report = json.loads(payload)
        if report['new_source_sha256'] != SHA:
            raise ValueError('Request export source differs')
        evidence.append(dict(path=str(path), sha256=expected))
        for function in report['functions']:
            address = int(function['address'],16)
            if address not in functions:
                continue
            if address in found:
                raise ValueError('Duplicate container root export coverage')
            if any(function.get(k) is not True for k in ('decompilation_completed', 'block_coverage_complete', 'direct_flow_coverage_complete')):
                raise ValueError('Incomplete request export')
            for row in function['instructions']:
                instruction(int(row['address'],16), bytes.fromhex(row['bytes']))
            found.add(address)
            h.fragments.append(function)
    if found != set(functions):
        raise ValueError('Requested function absent from supplied exports')
    if context.get('verify_whole_exports'):
        shapes = load('wire_source_shapes', HERE/'audit-launcher-shape-11318.py')
        for function in h.fragments:
            shapes.normalize_function(native, image, function)
    for address, expected in (leaves or {}).items():
        data = bytes.fromhex(expected)
        decoded = list(decoder.disasm(data,address))
        if sum(row.size for row in decoded) != len(data):
            raise ValueError('Request leaf has an instruction gap')
        for row in decoded:
            instruction(row.address,bytes(row.bytes))
    uc.mem_map(h.scratch,0x40000)
    pages.update(range(h.scratch,h.scratch+0x40000,4096))
    stop = h.scratch+0x3f000
    uc.mem_write(stop,b'\xc3')

    def finish(value=0):
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RAX,value)
        uc.reg_write(x.UC_X86_REG_RIP,int.from_bytes(uc.mem_read(stack,8),'little'))
        uc.reg_write(x.UC_X86_REG_RSP,stack+8)

    def add_fixture(address, handler):
        if address in allowed or address in functions or address in (leaves or {}):
            raise ValueError('Container fixture shadows native root/instruction/leaf')
        map_page(address)
        uc.mem_write(address,b'\xc3')
        h.fixtures[address] = handler

    def hook(machine,address,size,unused):
        if address == stop:
            machine.emu_stop()
        elif address in h.fixtures:
            h.fixtures[address](machine)
        elif address not in allowed:
            raise ValueError('Unreviewed request target '+hex(address))
    uc.hook_add(unicorn.UC_HOOK_CODE,hook)

    def call(address, receiver=0, budget=30000):
        stack = h.scratch+0x38008
        uc.reg_write(x.UC_X86_REG_RSP,stack)
        uc.mem_write(stack,struct.pack('<Q',stop))
        uc.reg_write(x.UC_X86_REG_RCX,receiver)
        uc.emu_start(address,0,count=budget)
        if uc.reg_read(x.UC_X86_REG_RIP) != stop:
            raise ValueError('Request instruction budget exhausted')
        return uc.reg_read(x.UC_X86_REG_RAX)

    h.finish, h.add_fixture, h.call = finish, add_fixture, call
    h.entry_stack, h.return_stack, h.stop = h.scratch+0x38008, h.scratch+0x38010, stop
    h.evidence = evidence
    return h
