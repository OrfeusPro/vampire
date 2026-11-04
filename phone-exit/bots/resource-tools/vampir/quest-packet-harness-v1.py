"""Proof-bound whole QuestSync/Tutorial execution with bounded fixture scopes.

This engine is deliberately independent of historical request harnesses. A
static receipt supplies roles; exact target exports supply complete code. Only
the declared packet scenario can earn native evidence; no runtime admission is
created here.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
SHA = re.compile('[0-9a-f]{64}')
FAMILIES = {'quest-sync': 18, 'tutorial-update': 13}
META = {'schema', 'family', 'exports', 'transfer_proof', 'verify_whole_exports'}
SCRATCH, SCRATCH_SIZE = 0x28000000, 0x40000
STACK_START, STACK_END, STACK_ENTRY = SCRATCH + 0x34000, SCRATCH + 0x3c000, SCRATCH + 0x38008
STOP = SCRATCH + 0x3f000
LIMIT = 32 * 1024 * 1024


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


def digest(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def tools():
    names = ('quest-reader-transfer-v1', 'quest-input-seed-v2', 'update-bindings',
             'knowledge-index', 'update-native-harness', 'native-publication-v2')
    return {**load('quest-reader-transfer-rules-v1').tools(),
            **{str(path): digest(path) for path in (Path(__file__).resolve(), *(HERE / (name + '.py') for name in names))}}


def runtime_inputs():
    return dict(native=load('update-native-harness').runtime_inputs(), python=sys.version,
        files={str(path): digest(path) for path in load('native-publication-v2').runtime_files()})


def pointer_document(pointer, category):
    if (not isinstance(pointer, dict) or set(pointer) != {'path', 'sha256'}
            or not isinstance(pointer['path'], str) or not isinstance(pointer['sha256'], str)
            or not SHA.fullmatch(pointer['sha256'])):
        raise ValueError('Quest packet exact proof pointer required')
    path = Path(pointer['path']).resolve()
    if (not path.is_relative_to(Path(category).resolve()) or path.name != 'manifest.json'
            or path.parent.name != pointer['sha256']):
        raise ValueError('Quest packet proof category or immutable address differs')
    with path.open('rb') as stream: raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT or hashlib.sha256(raw).hexdigest() != pointer['sha256']:
        raise ValueError('Quest packet proof changed or exceeds budget')
    return json.loads(raw)


def verify_files(files, aliases):
    if (not isinstance(files, dict) or not 1 <= len(files) <= 2048
            or any(not isinstance(value, str) or not SHA.fullmatch(value) or digest(path) != value
                   for path, value in files.items())):
        raise ValueError('Quest packet proof input/tool/runtime SHA changed')
    if any(str(Path(path).resolve()) != value for path, value in aliases.items()):
        raise ValueError('Quest packet proof input alias changed')


def admit(context, root, functions, leaves, exports, transfer_proof=None, source_store=None):
    """Recreate the static closure once for this exact frozen SourceStore."""
    family = context.get('family'); pointer = context.get('transfer_proof')
    if (family not in FAMILIES or context.get('schema') != 1 or type(context.get('schema')) is not int
            or context.get('verify_whole_exports') is not True
            or (transfer_proof is not None and transfer_proof != pointer)
            or exports != context.get('exports') or not isinstance(exports, dict) or not 1 <= len(exports) <= 12
            or any(not isinstance(run, str) or Path(run).name != run or not run.startswith('run-')
                   or not isinstance(sha, str) or not SHA.fullmatch(sha) for run, sha in exports.items())):
        raise ValueError('Quest packet context/family/export declaration differs')
    root = Path(root).resolve(); bindings = load('update-bindings')
    index = source_store.index if source_store is not None else load('knowledge-index').api()
    store = source_store if source_store is not None else bindings.SourceStore(index, root)
    if Path(store.root).resolve() != root: raise ValueError('Quest packet SourceStore root differs')
    proof = pointer_document(pointer, root / 'knowledge/quest-reader-transfer-proofs-v1')
    wrapper = load('quest-reader-transfer-v1'); rules = load('quest-reader-transfer-rules-v1')
    if (set(proof) != {'schema', 'recipe', 'method', 'inputs', 'package', 'native_consumer_verified',
                       'runtime_activated', 'profile_activated', 'limits'} or proof['schema'] != 1
            or proof['recipe'] != 'quest-reader-transfer-v1' or proof['method'] != 'static'
            or any(proof[key] is not False for key in ('native_consumer_verified', 'runtime_activated', 'profile_activated'))
            or proof['limits'] != wrapper.LIMITS):
        raise ValueError('Quest packet static receipt scope differs')
    inputs = proof['inputs']; rules.validate_package(proof['package'], inputs)
    projection = {key: value for key, value in context.items() if key not in META}
    if projection != proof['package']['target_contexts'][family]:
        raise ValueError('Quest packet context is not the exact proof projection')
    wanted = {int(value, 16) for value in context['functions'].values()}
    if (set(functions) != wanted or len(wanted) != FAMILIES[family]
            or leaves != {int(at, 16): raw for at, raw in context['leaves'].items()}):
        raise ValueError('Quest packet executed root/leaf scope differs')
    sha = context['source_sha256']
    if (not isinstance(sha, str) or not SHA.fullmatch(sha) or inputs['target_source_sha256'] != sha
            or Path(context['source']).resolve() != root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'):
        raise ValueError('Quest packet source path or full SHA differs')
    verify_files(inputs['files'], inputs['aliases'])
    if inputs['runtime'] != wrapper.runtime(index): raise ValueError('Quest packet static proof runtime differs')
    if any(inputs['tools'].get(path) != value for path, value in rules.tools().items()):
        raise ValueError('Quest packet static rule tools differ')
    seed = pointer_document(inputs['seed'], root / 'knowledge/quest-input-seed-proofs-v2')
    if (seed.get('recipe') != 'quest-input-seed-v2' or seed.get('method') != 'static'
            or seed.get('native_consumer_verified') is not False
            or seed['inputs']['target']['source_sha256'] != sha):
        raise ValueError('Quest packet seed source or method differs')
    for source in (inputs['baseline_source_sha256'], sha): store.source(source)
    selected_tools, selected_runtime = tools(), runtime_inputs()
    key = hashlib.sha256(canonical(dict(pointer=pointer, inputs=inputs, tools=selected_tools,
                                      runtime=selected_runtime))).hexdigest()
    memo = getattr(store, '_quest_packet_harness_v1_admitted', None)
    if memo is None: memo = store._quest_packet_harness_v1_admitted = {}
    if key not in memo:
        args = SimpleNamespace(root=root, knowledge=HERE / 'knowledge', source_store=store)
        rebuilt = rules.transfer(index, args, seed)
        if rebuilt != proof['package']: raise ValueError('Quest packet static receipt does not recreate from exact source')
        memo[key] = copy.deepcopy(rebuilt)
    elif memo[key] != proof['package']:
        raise ValueError('Quest packet invocation admission memo changed')
    verify_files(inputs['files'], inputs['aliases'])
    if tools() != selected_tools or runtime_inputs() != selected_runtime:
        raise ValueError('Quest packet harness tools/runtime changed during admission')
    return SimpleNamespace(proof=proof, pointer=copy.deepcopy(pointer), store=store,
        tools=selected_tools, runtime=selected_runtime, family=family, source_sha256=sha)


def make_harness(context, exports, functions, leaves=None, root=None, *, transfer_proof=None, source_store=None):
    native = load('build-native-entry-code'); root = Path(root) if root else native.ROOT
    admission = admit(context, root, set(functions), leaves or {}, exports, transfer_proof, source_store)
    sys.path.insert(0, str(HERE.parents[2] / '.tools/vampir-analysis'))
    import unicorn
    from unicorn import x86_const as x
    if unicorn.__version__ != '2.1.4' or native.capstone.__version__ != '5.0.6':
        raise ValueError('Pinned Quest packet runtime required')
    sha = admission.source_sha256; store = admission.store
    raw = store.source(sha); image = store.image(native, sha)
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64); decoder.detail = True
    pages, allowed, roots, evidence, fragments = set(), {}, set(functions), [], []
    readable, writable, source_ranges, input_ranges = [], [], [], []
    active = dict(running=False, previous=None, fixture=None, finished=False)
    h = SimpleNamespace(uc=uc, x=x, unicorn=unicorn, raw=raw, image=image,
        source=Path(context['source']), sha=sha, root=Path(root).resolve(), scratch=SCRATCH, stop=STOP,
        fixtures={}, fragments=fragments, evidence=evidence, entry_counts={}, call_counts=0,
        abi_checks=0, read_checks=0, write_checks=0, fixture_calls=0, admission=admission)

    def map_page(at):
        page = at & ~4095
        if page in pages: return
        if SCRATCH <= page < SCRATCH + SCRATCH_SIZE: raise ValueError('Quest source overlaps scratch')
        uc.mem_map(page, 4096); pages.add(page)
        try: offset = image.offset(page - image.pe.base)
        except ValueError: return
        uc.mem_write(page, raw[offset:offset + 4096])

    def add_instruction(row):
        at = row['address']; data = bytes.fromhex(row['bytes'])
        offset = image.offset(at - image.pe.base)
        instructions = list(decoder.disasm(data, at))
        if raw[offset:offset + len(data)] != data or len(instructions) != 1 or instructions[0].size != len(data):
            raise ValueError('Quest packet source instruction/boundary differs')
        if at in allowed and allowed[at] != row: raise ValueError('Quest packet instruction declarations conflict')
        allowed[at] = row; map_page(at); map_page(at + len(data) - 1)

    found = set(); export_files = {}
    bindings = load('update-bindings')
    for run, expected in exports.items():
        path = Path(root) / 'ghidra/request-exports' / sha / run / 'details.json'
        with path.open('rb') as stream: payload = stream.read(LIMIT + 1)
        if len(payload) > LIMIT or hashlib.sha256(payload).hexdigest() != expected:
            raise ValueError('Quest packet target export changed or exceeds budget')
        report = json.loads(payload)
        if report.get('new_source_sha256', report.get('source_sha256')) != sha:
            raise ValueError('Quest packet target export source differs')
        export_files[str(path.resolve())] = expected; evidence.append(dict(path=str(path), sha256=expected))
        for function in report.get('functions', []):
            at = int(function['address'], 16)
            if at not in roots: continue
            if function.get('decompilation_completed') is not True: raise ValueError('Quest packet target export incomplete')
            whole = bindings.rows(native, image, at)
            actual = [(int(row['address'], 16), row['bytes'].lower()) for row in function.get('instructions', [])]
            if actual != [(row['address'], row['bytes'].lower()) for row in whole]:
                raise ValueError('Quest packet target export lacks exact whole unwind span')
            for row in whole: add_instruction(row)
            if at not in found: fragments.append(function)
            found.add(at)
    if found != roots: raise ValueError('Quest packet target export root coverage incomplete')
    leaf_api = load('login-input-transfer-rules')
    for at, text in (leaves or {}).items():
        data = bytes.fromhex(text)
        for row in leaf_api.leaf_rows(native, image, at, data): add_instruction(row)
    package = admission.proof['package']; relation = package['relation']
    for item in relation['tables']:
        at = int(item['target'], 16); data = bytes.fromhex(item['bytes'])
        offset = image.offset(at - image.pe.base)
        if raw[offset:offset + len(data)] != data: raise ValueError('Quest packet target table changed')
        map_page(at); map_page(at + len(data) - 1); source_ranges.append((at, at + len(data)))
    for table, slot, target in context['bindings']:
        at = int(table, 16) + int(slot, 16); offset = image.offset(at - image.pe.base)
        if struct.unpack_from('<Q', raw, offset)[0] != int(target, 16):
            raise ValueError('Quest packet target used table binding differs')
    boundaries = {int(item['target'], 16): item for item in relation['boundaries']
                  if item['consumer'] in (context['family'], 'shared-input')}
    if set(boundaries) & (set(allowed) | roots | set(leaves or {})):
        raise ValueError('Quest packet fixture overlaps executed code')
    fixture_callers = {at: set() for at in boundaries}
    reserve = context['fixtures'].get('reserve')
    for at, row in allowed.items():
        if not row['call']: continue
        target = row['direct_target']
        if target in boundaries: fixture_callers[target].add(at + len(bytes.fromhex(row['bytes'])))
        elif (target is None and reserve and row['operands'] == 'qword ptr [rax + 8]'
                and int(context['functions']['vector'], 16) <= at < int(context['functions']['vector'], 16) + 128):
            fixture_callers[int(reserve, 16)].add(at + len(bytes.fromhex(row['bytes'])))
    for at in boundaries: map_page(at)
    uc.mem_map(SCRATCH, SCRATCH_SIZE); uc.mem_write(STOP, b'\xc3')

    def within(address, size, ranges):
        return type(address) is int and type(size) is int and size >= 0 and any(
            lo <= address and address + size <= hi for lo, hi in ranges)

    def add_range(address, size, ranges):
        if (active['running'] and active['fixture'] is None) or not within(address, size, [(SCRATCH, STACK_START)]):
            raise ValueError('Quest packet data permission is outside bounded scratch')
        if not 0 <= size <= 0x30000: raise ValueError('Quest packet data permission budget exceeded')
        if size: ranges.append((address, address + size))
        if len(ranges) > 4096: raise ValueError('Quest packet data permission count exceeded')

    def allow_read(address, size):
        add_range(address, size, readable)
        input_ranges.append((address, address + size))
    def allow_write(address, size):
        add_range(address, size, writable); add_range(address, size, readable)
    def release_region(address, size):
        if active['fixture'] is None:
            raise ValueError('Quest storage can only be released by a fixture')
        region = (address, address + size)
        writable.remove(region)
        readable.remove(region)
    def reset_regions():
        if active['running']: raise ValueError('Quest packet cannot reset active memory permissions')
        readable.clear(); writable.clear(); input_ranges.clear()
    def write(address, data):
        data = bytes(data)
        fixture_stack = [(STACK_START + 16, STACK_END - 16)] if active['fixture'] is not None else []
        if not within(address, len(data), writable + fixture_stack):
            raise ValueError('Quest fixture writes outside declared output')
        uc.mem_write(address, data); h.write_checks += 1

    def finish(value=0):
        current = active['fixture']
        if current is None: raise ValueError('Quest fixture finish outside declared fixture')
        address, expected_stack, expected_return = current
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        if stack != expected_stack or int.from_bytes(uc.mem_read(stack, 8), 'little') != expected_return:
            raise ValueError('Quest fixture changed its return boundary')
        uc.reg_write(x.UC_X86_REG_RAX, value); uc.reg_write(x.UC_X86_REG_RSP, stack + 8)
        uc.reg_write(x.UC_X86_REG_RIP, expected_return); active['fixture'] = None

    def add_fixture(address, handler):
        if active['running'] or address not in boundaries or address in h.fixtures or not callable(handler):
            raise ValueError('Quest packet fixture is undeclared, duplicate or active')
        if not fixture_callers[address]: raise ValueError('Quest packet fixture lacks a reviewed caller')
        h.fixtures[address] = handler

    def code_hook(machine, address, size, unused):
        if address == STOP:
            active['finished'] = True; machine.emu_stop(); return
        if address in boundaries:
            if address not in h.fixtures: raise ValueError('Quest packet fixture handler missing: ' + hex(address))
            previous = active['previous']; stack = machine.reg_read(x.UC_X86_REG_RSP)
            if previous is None or not previous['call'] or not within(stack, 8, [(STACK_START + 16, STACK_END - 16)]):
                raise ValueError('Quest packet fixture entry lacks native call provenance')
            returning = int.from_bytes(machine.mem_read(stack, 8), 'little')
            if returning not in fixture_callers[address] or returning != previous['address'] + len(bytes.fromhex(previous['bytes'])):
                raise ValueError('Quest packet fixture caller/return boundary differs')
            h.entry_counts[address] = h.entry_counts.get(address, 0) + 1; h.fixture_calls += 1
            active['fixture'] = (address, stack, returning); h.fixtures[address](machine)
            if active['fixture'] is not None: raise ValueError('Quest fixture did not complete its reviewed return')
            return
        if address not in allowed or size != len(bytes.fromhex(allowed[address]['bytes'])):
            raise ValueError('Unreviewed Quest packet execution target: ' + hex(address))
        if address in roots or address in (leaves or {}): h.entry_counts[address] = h.entry_counts.get(address, 0) + 1
        active['previous'] = allowed[address]

    def memory_hook(machine, access, address, size, value, unused):
        stack = [(STACK_START + 16, STACK_END - 16)]
        if access == unicorn.UC_MEM_WRITE:
            if not within(address, size, writable + stack):
                raise ValueError('Quest packet native write outside declared output: ' + hex(address))
            h.write_checks += 1
        else:
            if not within(address, size, readable + source_ranges + stack):
                raise ValueError('Quest packet native read outside declared input: ' + hex(address))
            h.read_checks += 1
    uc.hook_add(unicorn.UC_HOOK_CODE, code_hook)
    uc.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, memory_hook)

    copy_boundary = next(item for item in relation['boundaries'] if item['consumer'] == 'shared-input' and item['role'] == 'memcpy')
    def copy_fixture(machine):
        dest, source, count = [machine.reg_read(reg) for reg in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        stack = [(STACK_START + 16, STACK_END - 16)]
        if count > 8 or not within(source, count, input_ranges) or not within(dest, count, writable + stack):
            raise ValueError('Quest packet memcpy input/output bound differs')
        if count and dest < source + count and source < dest + count:
            raise ValueError('Quest packet memcpy ranges overlap')
        if count:
            machine.mem_write(dest, bytes(machine.mem_read(source, count)))
            h.write_checks += 1
        finish(dest)
    add_fixture(int(copy_boundary['target'], 16), copy_fixture)

    nonvolatile = ('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15')
    volatile = ('RAX', 'RCX', 'RDX', 'R8', 'R9', 'R10', 'R11')
    xmm_saved = tuple('XMM' + str(i) for i in range(6, 16))
    def call(address, receiver=0, budget=30000, *, rdx=0, r8=0, r9=0, stack_args=()):
        if active['running'] or address not in roots | set(leaves or {}):
            raise ValueError('Quest packet call entry is outside exact root/leaf scope')
        if type(budget) is not int or not 1 <= budget <= 1000000 or len(stack_args) > 8:
            raise ValueError('Quest packet call instruction/argument budget exceeded')
        for value in (receiver, rdx, r8, r9, *stack_args):
            if type(value) is not int or not 0 <= value < 1 << 64: raise ValueError('Quest packet Win64 argument differs')
        uc.mem_write(STACK_START, b'\xcd' * (STACK_END - STACK_START))
        uc.mem_write(STACK_START, b'\xd1' * 16); uc.mem_write(STACK_END - 16, b'\xd2' * 16)
        for name in volatile: uc.reg_write(getattr(x, 'UC_X86_REG_' + name), 0)
        saved = {}
        for i, name in enumerate(nonvolatile):
            saved[name] = 0x1a2b300000000000 + i * 0x10101
            uc.reg_write(getattr(x, 'UC_X86_REG_' + name), saved[name])
        for i in range(16): uc.reg_write(getattr(x, 'UC_X86_REG_XMM' + str(i)), 0)
        for i, name in enumerate(xmm_saved):
            saved[name] = 0x123456789abcdef00112233445566770 + i
            uc.reg_write(getattr(x, 'UC_X86_REG_' + name), saved[name])
        uc.reg_write(x.UC_X86_REG_EFLAGS, 0x202)
        uc.reg_write(x.UC_X86_REG_RSP, STACK_ENTRY); uc.mem_write(STACK_ENTRY, struct.pack('<Q', STOP))
        uc.mem_write(STACK_ENTRY + 8, bytes(32))
        for i, value in enumerate(stack_args): uc.mem_write(STACK_ENTRY + 0x28 + i * 8, struct.pack('<Q', value))
        for reg, value in ((x.UC_X86_REG_RCX, receiver), (x.UC_X86_REG_RDX, rdx),
                           (x.UC_X86_REG_R8, r8), (x.UC_X86_REG_R9, r9)): uc.reg_write(reg, value)
        active.update(running=True, previous=None, fixture=None, finished=False)
        try:
            uc.emu_start(address, 0, count=budget)
            if not active['finished'] or uc.reg_read(x.UC_X86_REG_RIP) != STOP:
                raise ValueError('Quest packet instruction budget exhausted or invalid return')
            if uc.reg_read(x.UC_X86_REG_RSP) != STACK_ENTRY + 8:
                raise ValueError('Quest packet Win64 stack return differs')
            if any(uc.reg_read(getattr(x, 'UC_X86_REG_' + name)) != value for name, value in saved.items()):
                raise ValueError('Quest packet Win64 nonvolatile register changed')
            if bytes(uc.mem_read(STACK_START, 16)) != b'\xd1' * 16 or bytes(uc.mem_read(STACK_END - 16, 16)) != b'\xd2' * 16:
                raise ValueError('Quest packet stack guard changed')
            h.abi_checks += 1; h.call_counts += 1
            return uc.reg_read(x.UC_X86_REG_RAX)
        finally:
            active.update(running=False, fixture=None, previous=None)

    def validate():
        if active['running']: raise ValueError('Quest packet final validation during execution')
        actual = pointer_document(admission.pointer, Path(root) / 'knowledge/quest-reader-transfer-proofs-v1')
        if actual != admission.proof: raise ValueError('Quest packet selected proof changed')
        verify_files(actual['inputs']['files'], actual['inputs']['aliases'])
        verify_files(export_files, {})
        if tools() != admission.tools or runtime_inputs() != admission.runtime:
            raise ValueError('Quest packet code or runtime changed during execution')
        admission.store.validate()
        return dict(source_sha256=sha, target_exports_verified=True, native_execution=True,
            abi_checks=h.abi_checks, call_counts=h.call_counts, read_checks=h.read_checks,
            write_checks=h.write_checks, fixture_calls=h.fixture_calls,
            runtime_activated=False, profile_activated=False)
    h.finish, h.add_fixture, h.call, h.validate = finish, add_fixture, call, validate
    h.allow_read, h.allow_write, h.reset_regions, h.write = allow_read, allow_write, reset_regions, write
    h.release_region = release_region
    return h
