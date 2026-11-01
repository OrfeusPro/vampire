"""Exact five-root/one-leaf native admission for bounded buffer transport."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ROLES = {'vector.resize', 'vector.grow', 'queue.append', 'transport', 'archive.raw'}
ENTRY_ROLES = {'resize': 'vector.resize', 'append': 'queue.append',
               'transport': 'transport', 'archive': 'archive.raw'}


def load(name, path=None):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path or HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def runtime_inputs():
    import importlib.metadata
    result = {}
    for name in ('capstone', 'unicorn'):
        found = [d for d in importlib.metadata.distributions(
            path=[str(HERE.parents[2] / '.tools/vampir-analysis')])
            if d.metadata['Name'].lower() == name]
        if len(found) != 1:
            raise ValueError('Missing or ambiguous buffer native runtime')
        result[name] = dict(version=found[0].version,
            record_sha256=hashlib.sha256((found[0].read_text('RECORD') or '').encode()).hexdigest())
    return result


def check_scope(context, functions, leaves, exports):
    if (context.get('family') != 'buffer-transport' or context.get('format') != 'buffer-transport-v1'
            or not context.get('transfer_proof') or set(context.get('functions', {})) != ROLES
            or set(functions) != {int(at, 16) for at in context['functions'].values()}
            or len(functions) != 5 or len(leaves) != 1
            or list(leaves.values()) != ['895108c3']
            or leaves != {int(at, 16): raw for at, raw in context['leaves'].items()}
            or set(functions) & set(leaves) or exports != context.get('exports')
            or not 1 <= len(exports) <= 8
            or any(k in context for k in ('tails', 'function_budget', 'budget_scope',
                'native_admission', 'native_input', 'native_handler'))):
        raise ValueError('Buffer transport exact five-root/one-leaf admission differs')


class EntrySequence:
    """Only the mode's declared top-level entries; native helpers stay nested."""
    def __init__(self, functions):
        self.functions = functions
        self.phase, self.active, self.expected, self.history = 'unstarted', False, [], []

    def begin_case(self, spec):
        if self.active or self.phase not in ('unstarted', 'complete'):
            raise ValueError('Previous buffer native case is incomplete')
        role = ENTRY_ROLES.get(spec.get('mode'))
        steps = spec.get('steps')
        if role is None or not isinstance(steps, list) or not steps:
            raise ValueError('Buffer native entry mode/steps differ')
        self.expected = [self.functions[role]] * len(steps)
        self.phase, self.history = 'ready', []

    def enter(self, address):
        if (self.active or self.phase != 'ready' or len(self.history) >= len(self.expected)
                or address != self.expected[len(self.history)]):
            raise ValueError('Undeclared or nested coordinator buffer entry')
        self.active = True

    def finish(self, successful):
        if not self.active:
            raise ValueError('Buffer native entry was not active')
        self.active = False
        if not successful:
            self.phase = 'failed'
            return
        self.history.append(self.expected[len(self.history)])
        self.phase = 'complete' if len(self.history) == len(self.expected) else 'ready'


def check_fixture_address(address, spans):
    if type(address) is not int or address < 0 or any(lo <= address < hi for lo, hi in spans):
        raise ValueError('Buffer fixture shadows admitted native instructions')


def export_identity(function):
    rows = [(int(row['address'], 16), row['bytes'].lower()) for row in function['instructions']]
    if len(rows) != len({at for at, _ in rows}):
        raise ValueError('Buffer export repeats an instruction')
    return tuple(sorted(rows))


def admit(context, root, functions, leaves, exports):
    check_scope(context, functions, leaves, exports)
    index = load('knowledge-index').api()
    adapter = load('update-native-buffer-transport').select('buffer-transport')
    args = SimpleNamespace(root=Path(root), knowledge=HERE / 'knowledge')
    args.source_store = load('update-bindings').SourceStore(index, args.root)
    if adapter.roots(context) != functions:
        raise ValueError('Buffer executed roots differ')
    adapter.validate(index, args, context)
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    image = args.source_store.image(native, context['source_sha256'])
    adapter.export_coverage(args.root, context, native, bindings, image)
    args.source_store.validate()


def make_harness(context, root=None):
    native = load('build-native-entry-code')
    sys.path.insert(0, str(HERE.parents[2] / '.tools/vampir-analysis'))
    import unicorn
    from unicorn import x86_const as x
    if unicorn.__version__ != '2.1.4' or native.capstone.__version__ != '5.0.6':
        raise ValueError('Pinned buffer native runtime required')
    sha = context['source_sha256']
    if not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{64}', sha):
        raise ValueError('Explicit full buffer source SHA required')
    root = Path(root) if root else native.ROOT
    source = root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
    if Path(context['source']).resolve() != source.resolve():
        raise ValueError('Buffer context source path differs')
    functions = {int(at, 16) for at in context['functions'].values()}
    leaves = {int(at, 16): raw for at, raw in context['leaves'].items()}
    exports = context['exports']
    admit(context, root, functions, leaves, exports)
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('Buffer snapshot source SHA changed')
    image = native.Image(raw)
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    pages, allowed, identities, spans = set(), set(), {}, []
    h = SimpleNamespace(uc=uc, x=x, raw=raw, image=image, source=source, sha=sha,
        root=root, scratch=0x28000000, fixtures={}, fragments=[], evidence=[])

    def map_page(address):
        page = address & ~4095
        if page in pages:
            return
        uc.mem_map(page, 4096)
        pages.add(page)
        try:
            off = image.offset(page - image.pe.base)
        except ValueError:
            return
        uc.mem_write(page, raw[off:off + 4096])

    def instruction(address, data):
        off = image.offset(address - image.pe.base)
        decoded = list(decoder.disasm(data, address))
        if raw[off:off + len(data)] != data or len(decoded) != 1 or decoded[0].size != len(data):
            raise ValueError('Buffer instruction differs from exact source/boundary')
        allowed.add(address)
        spans.append((address, address + len(data)))
        map_page(address)
        map_page(address + len(data) - 1)
        for operand in decoded[0].operands:
            if operand.type == native.X86_OP_MEM and operand.mem.base == native.X86_REG_RIP:
                target = address + len(data) + operand.mem.disp
                map_page(target)
                map_page(target + 511)

    for run, expected in exports.items():
        path = root / 'ghidra/request-exports' / sha / run / 'details.json'
        payload = path.read_bytes()
        report = json.loads(payload)
        if hashlib.sha256(payload).hexdigest() != expected or report['new_source_sha256'] != sha:
            raise ValueError('Buffer export source/hash changed')
        h.evidence.append(dict(path=str(path), sha256=expected))
        for function in report['functions']:
            address = int(function['address'], 16)
            if address not in functions:
                continue
            if any(function.get(key) is not True for key in (
                    'decompilation_completed', 'block_coverage_complete', 'direct_flow_coverage_complete')):
                raise ValueError('Incomplete buffer whole export')
            identity = export_identity(function)
            if address in identities:
                if identity != identities[address]:
                    raise ValueError('Duplicate buffer export differs')
                continue
            for row in function['instructions']:
                instruction(int(row['address'], 16), bytes.fromhex(row['bytes']))
            identities[address] = identity
            h.fragments.append(function)
    if set(identities) != functions:
        raise ValueError('Buffer whole function absent from supplied exports')
    for address, expected in leaves.items():
        data = bytes.fromhex(expected)
        decoded = list(decoder.disasm(data, address))
        if sum(row.size for row in decoded) != len(data):
            raise ValueError('Buffer leaf instruction gap')
        for row in decoded:
            instruction(row.address, bytes(row.bytes))
    imports = load('build-object-zero-init-code')
    h.memory_imports = {}
    for name in ('memcpy', 'memmove', 'memset'):
        at = int(context['helpers'][name], 16)
        off = image.offset(at - image.pe.base)
        code = raw[off:off + 6]
        if code[:2] != b'\xff\x25':
            raise ValueError('Buffer memory import thunk differs')
        slot = at + 6 + struct.unpack_from('<i', code, 2)[0]
        binding = imports.import_at(raw, image, slot)
        if (binding['dll'].lower(), binding['name']) != ('vcruntime140.dll', name):
            raise ValueError('Buffer memory import identity differs')
        h.memory_imports[name] = binding
    core = load('portable-native-family')
    h.wire = core.checked(root, context['wire_context'], 'generated-native-contexts')
    h.wire_check = core.checked(root, context['wire_check'], 'native-adapter-checks')
    uc.mem_map(h.scratch, 0x200000)
    pages.update(range(h.scratch, h.scratch + 0x200000, 4096))
    stop = h.scratch + 0x3f000
    uc.mem_write(stop, b'\xc3')

    def finish(value=0):
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RAX, value)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(stack, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, stack + 8)

    def add_fixture(address, handler):
        check_fixture_address(address, spans)
        if address in h.fixtures:
            raise ValueError('Duplicate buffer fixture address')
        map_page(address)
        # Source helper/import bytes remain unchanged; code hooks provide only
        # the declared opaque effect before the original instruction executes.
        h.fixtures[address] = handler

    def hook(machine, address, size, unused):
        if address == stop:
            machine.emu_stop()
        elif address in h.fixtures:
            h.fixtures[address](machine)
        elif address not in allowed:
            raise ValueError('Unreviewed buffer native target ' + hex(address))
    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    h.entries = EntrySequence({key: int(at, 16) for key, at in context['functions'].items()})

    def call(address, receiver=0, second=0, third=0, fourth=0, budget=100000):
        h.entries.enter(address)
        successful, h.call_active = False, True
        uc.reg_write(x.UC_X86_REG_RSP, h.entry_stack)
        uc.mem_write(h.entry_stack, struct.pack('<Q', stop))
        for name, value in zip(('RCX', 'RDX', 'R8', 'R9'), (receiver, second, third, fourth)):
            uc.reg_write(getattr(x, 'UC_X86_REG_' + name), value)
        try:
            uc.emu_start(address, 0, count=budget)
            successful = uc.reg_read(x.UC_X86_REG_RIP) == stop
            if not successful:
                raise ValueError('Buffer native instruction budget exhausted')
        finally:
            h.call_active = False
            h.entries.finish(successful)
        return uc.reg_read(x.UC_X86_REG_RAX)

    h.call_active = False
    h.entry_stack, h.return_stack, h.stop = h.scratch + 0x38008, h.scratch + 0x38010, stop
    h.instruction_spans = tuple(spans)
    h.map_source, h.finish, h.add_fixture, h.call = map_page, finish, add_fixture, call
    h.begin_case = h.entries.begin_case
    return h
