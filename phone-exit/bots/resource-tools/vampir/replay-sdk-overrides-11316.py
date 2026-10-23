"""Execute source-bound SDK override code in synthetic memory, without network."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
SHA = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
EXPORTS = {
    'run-0716c15e22dc': '4c40e76365d77eff13cf541ef2674797016ccf6e0a6d2b0664cf1d761a8dcfa6',
    'run-9dc981740f54': 'f9ea52df7f73a60191e0d3515ad7585237925c1b7ad7839dff3f142ea7f9cd36',
    'run-5e52997758ac': '9aba1113b3baf9838e6721a9a73b5360a56b566e540d0627c5cfaeab9f194954',
    'run-d490839a48f4': 'ba186c8e32fccaecc4a5a4dae04b8df9d2c667327bec1309a6d5a9ce04fa0bb1',
}
LEAVES = {
    0x14145f1e0: (0x47, '591d6b9ae17a1ebc090ce3e9b853202de35bfecd86a36324752503d4548097c0'),
    0x14145f230: (0x4b, '0f0fe1b437f5ff2398fdd154b8fc18567f6e984818a98ee51ab1aa97cd3ec41a'),
    0x144552240: (7, '9a8cf11a18ce9832afd8414af78f122b6b0a6dcb4f9a1ff8e43e25c4ab5c8032'),
}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def replay(root=None):
    native = load('override_11316_native', HERE / 'build-native-entry-code.py')
    sys.path.insert(0, str(HERE.parents[2] / '.tools/vampir-analysis'))
    import unicorn
    from unicorn import x86_const as x
    if unicorn.__version__ != '2.1.4' or native.capstone.__version__ != '5.0.6':
        raise ValueError('Pinned analysis runtime required')
    root = Path(root) if root else native.ROOT
    source = root / 'client-code-snapshots' / SHA / 'ProjectRED-Win64-Shipping.exe'
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA:
        raise ValueError('Override source SHA changed')
    image = native.Image(raw)
    imports = load('override_11316_imports', HERE / 'build-object-zero-init-code.py')
    copy = 0x1487f5ab9
    copy_offset = image.offset(copy - image.pe.base)
    if raw[copy_offset:copy_offset + 2] != b'\xff\x25':
        raise ValueError('Override copy import thunk differs')
    slot = copy + 6 + struct.unpack_from('<i', raw, copy_offset + 2)[0]
    copy_import = imports.import_at(raw, image, slot)
    if (copy_import['dll'].lower(), copy_import['name']) != ('vcruntime140.dll', 'memcpy'):
        raise ValueError('Override copy import identity differs')
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    pages, allowed, evidence = set(), set(), []

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

    def add_instruction(address, data):
        off = image.offset(address - image.pe.base)
        if raw[off:off + len(data)] != data:
            raise ValueError('Override instruction differs from source')
        instructions = list(decoder.disasm(data, address))
        if len(instructions) != 1 or instructions[0].size != len(data):
            raise ValueError('Override instruction boundary differs')
        allowed.add(address)
        map_page(address)
        map_page(address + len(data) - 1)
        for operand in instructions[0].operands:
            if operand.type == native.X86_OP_MEM and operand.mem.base == native.X86_REG_RIP:
                target = address + len(data) + operand.mem.disp
                map_page(target)
                map_page(target + 255)

    for run, expected in EXPORTS.items():
        path = root / 'ghidra/request-exports' / SHA / run / 'details.json'
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != expected:
            raise ValueError('Override export SHA changed')
        report = json.loads(payload)
        if report['new_source_sha256'] != SHA:
            raise ValueError('Override export source differs')
        evidence.append(dict(path=str(path), sha256=expected))
        for function in report['functions']:
            if not function['decompilation_completed']:
                raise ValueError('Incomplete override export')
            for row in function['instructions']:
                add_instruction(int(row['address'], 16), bytes.fromhex(row['bytes']))
    leaves = []
    for address, (size, expected) in LEAVES.items():
        off = image.offset(address - image.pe.base)
        data = raw[off:off + size]
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('Reviewed override leaf changed')
        instructions = list(decoder.disasm(data, address))
        if sum(i.size for i in instructions) != size or instructions[-1].mnemonic != 'ret':
            raise ValueError('Override leaf coverage differs')
        boundaries = {i.address for i in instructions}
        for ins in instructions:
            if ins.mnemonic.startswith('j'):
                if ins.operands[0].type != native.capstone.x86.X86_OP_IMM or ins.operands[0].imm not in boundaries:
                    raise ValueError('Override leaf branch leaves reviewed body')
            add_instruction(ins.address, bytes(ins.bytes))
        leaves.append(dict(address=hex(address), bytes=data.hex(), sha256=expected))

    scratch = 0x26000000
    uc.mem_map(scratch, 0x40000)
    settings, class_object, environment, sdk, command, stop = [scratch + v for v in
        (0x11000, 0x14000, 0x15000, 0x16000, 0x18000, 0x3f000)]
    heap, options, events = [scratch + 0x20000], {}, []
    globals_allowed = {0x14b5e5f88, 0x14b5e5f78, 0x14b5e5fc8, 0x14b5e5fb8}
    fixtures = {0x141426b30, 0x141436ed0, 0x1444b1fe0, 0x14560ad80,
                0x141439470, 0x14152d5c0, 0x14158edf0, 0x1417cba90,
                0x141483080, 0x1487e914c, 0x1487f5ab9}
    for address in fixtures:
        map_page(address)
        uc.mem_write(address, b'\xc3')
    uc.mem_write(stop, b'\xc3')

    def allocate(size):
        pointer = heap[0]
        heap[0] += (size + 15) & ~15
        if heap[0] > scratch + 0x2e000:
            raise ValueError('Override fixture heap bound')
        return pointer

    def literal(address):
        off = image.offset(address - image.pe.base)
        data = raw[off:off + 256]
        end = next((i for i in range(0, 254, 2) if data[i:i + 2] == bytes(2)), None)
        if end is None:
            raise ValueError('Override literal bound')
        return data[:end].decode('utf-16le')

    def put_string(destination, text):
        if not (scratch <= destination <= scratch + 0x40000 - 16 or destination in globals_allowed):
            raise ValueError('Override string destination bound')
        payload = text.encode('utf-16le') + bytes(2)
        if len(payload) > 256:
            raise ValueError('Override fixture string length bound')
        pointer = allocate(len(payload)) if text else 0
        if pointer:
            uc.mem_write(pointer, payload)
        count = len(payload) // 2 if text else 0
        uc.mem_write(destination, struct.pack('<QII', pointer, count, count))

    def finish(value=0):
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RAX, value)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(stack, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, stack + 8)

    def hook(machine, address, size, unused):
        if address == stop:
            machine.emu_stop()
            return
        if address not in fixtures:
            if address not in allowed:
                raise ValueError('Unreviewed override target ' + hex(address))
            return
        a, b, c = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        result = 0
        if address == 0x141426b30:
            put_string(a, literal(b))
            result = a
        elif address == 0x141436ed0:
            if a not in (settings + 0x28, settings + 0x38, settings + 0x98) or not 0 <= b <= 128:
                raise ValueError('Override capacity fixture bound')
            machine.mem_write(a, struct.pack('<Q', allocate(b * 2) if b else 0))
            machine.mem_write(a + 12, struct.pack('<I', b))
            result = a
        elif address == 0x1487f5ab9:
            if not 0 <= c <= 256 or not all(scratch <= p <= scratch + 0x40000 - c for p in (a, b)):
                raise ValueError('Override copy fixture bound')
            machine.mem_write(a, bytes(machine.mem_read(b, c)))
            result = a
        elif address == 0x1444b1fe0:
            result = class_object
        elif address == 0x14560ad80:
            result = sdk if options['sdk_present'] else 0
        elif address == 0x141439470:
            if a != environment + 0x48:
                raise ValueError('Override environment receiver differs')
            put_string(b, options['environment'])
            result = b
        elif address == 0x14152d5c0:
            result = command
        elif address == 0x14158edf0:
            if a != command or literal(b) != 'NMENV=':
                raise ValueError('Override parser fixture key differs')
            if options['nmenv'] is not None:
                put_string(c, options['nmenv'])
                result = 1
            events.append(dict(key='NMENV=', present=options['nmenv'] is not None))
        elif address == 0x1417cba90:
            if a != settings:
                raise ValueError('Override base constructor receiver differs')
        elif address not in (0x141483080, 0x1487e914c):
            raise ValueError('Unreviewed override fixture')
        finish(result)

    uc.hook_add(unicorn.UC_HOOK_CODE, hook)

    def call(address, prefix_stop=None):
        stack = scratch + 0x38000
        uc.reg_write(x.UC_X86_REG_RSP, stack)
        uc.mem_write(stack, struct.pack('<Q', stop))
        uc.reg_write(x.UC_X86_REG_RCX, settings)
        uc.emu_start(address, prefix_stop or 0, count=30000)
        if uc.reg_read(x.UC_X86_REG_RIP) != (prefix_stop or stop):
            raise ValueError('Override native instruction budget exhausted')

    def text(address):
        pointer, count, capacity = struct.unpack('<QII', bytes(uc.mem_read(address, 16)))
        if not 0 <= count <= capacity <= 128:
            raise ValueError('Override output FString bound')
        return bytes(uc.mem_read(pointer, (count - 1) * 2)).decode('utf-16le') if count else ''

    cases = []
    def run(env, market, sdk_present=True, sdk_handle=True):
        options.update(environment=env, nmenv=market, sdk_present=sdk_present)
        events.clear()
        heap[0] = scratch + 0x20000
        uc.mem_write(settings - 16, b'\xa5' * 0x250)
        uc.mem_write(class_object + 0x110, struct.pack('<Q', settings))
        uc.mem_write(sdk + 0x38, struct.pack('<Q', int(sdk_handle)))
        uc.mem_write(0x14b5e6ce0, struct.pack('<Q', environment))
        uc.mem_write(0x14b5632e0, bytes(1))
        call(0x1444b3290, 0x1444b3339)
        for entry in (0x14125b710, 0x14125b740, 0x14125b770, 0x14125b7d0):
            call(entry)
        uc.mem_write(settings + 0xc8, b'\xff')
        call(0x1456579d0)
        actual = dict(market=text(settings + 0x28), game_code=text(settings + 0x38),
                      client_id=text(settings + 0x98), build_code=uc.mem_read(settings + 0x48, 1)[0],
                      sdk_zone=uc.mem_read(settings + 0x49, 1)[0], raw_c8=uc.mem_read(settings + 0xc8, 1)[0])
        if bytes(uc.mem_read(settings - 16, 16)) != b'\xa5' * 16 or bytes(uc.mem_read(settings + 0x228, 16)) != b'\xa5' * 16:
            raise ValueError('Override crossed settings canaries')
        if len(events) != int(sdk_present and sdk_handle):
            raise ValueError('Override parser gate differs')
        cases.append(dict(environment=env, nmenv=market, sdk_present=sdk_present, sdk_handle=sdk_handle,
                          actual=actual, events=events.copy(), canaries_unchanged=True))

    for env in ('real', 'REAL', 'Real', 'rEaL', '', 'dev', 'alpha', 'dr', 'production', ' real', 'real ', 'reals', 'réal'):
        for market in (None, '', 'nmp', 'NMP', 'epicgames', 'EPICGAMES', 'gpgpc', 'unknown'):
            run(env, market)
    run('real', 'epicgames', sdk_present=False)
    run('real', 'epicgames', sdk_handle=False)
    return dict(schema=1, source=str(source), source_sha256=SHA, evidence=evidence, leaves=leaves,
        copy_import=copy_import, cases=cases,
        dependencies={name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in
                      ('replay-sdk-overrides-11316.py', 'build-native-entry-code.py', 'extract-native-enums.py', 'build-object-zero-init-code.py')},
        fixtures=[hex(a) for a in sorted(fixtures)],
        limits=['Actual settings prefix, four initializers, override, market selector/getter, both comparators and shared tail execute.',
                'Class/CDO, singleton handles, environment string, command-line parser output, FString storage/capacity, memcpy/free and exit registration are fixtures.',
                'Logging disabled; no actual UObject registration, full startup, active game inputs, network, auth or GMC2 URL/headers.'])


if __name__ == '__main__':
    report = replay()
    audit = load('override_11316_audit', HERE / 'audit-client-release.py')
    native = load('override_11316_root', HERE / 'build-native-entry-code.py')
    path = audit.save_snapshot(native.ROOT / 'code-clues/sdk-overrides-11316', report)
    print(json.dumps(dict(report=str(path), cases=len(report['cases']))))
