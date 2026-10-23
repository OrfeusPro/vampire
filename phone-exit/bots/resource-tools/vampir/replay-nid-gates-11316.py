"""Current NID availability gates and account additions; no browser/network."""
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = 0x1450e3c80
EXPORTS = {'run-988ec3bf8f0a': 'ac636f8488eb37a37646b4213878b4db9bb4c7567e5eddb2569195e346c0f6fd'}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def replay(root=None):
    harness = load('nid_gates_harness', HERE/'native-request-harness-11316.py')
    h = harness.make_harness(EXPORTS, {ROOT}, root=root)
    rbp, context, settings, account = [h.scratch+n for n in (0x10000, 0x18000, 0x19000, 0x1a000)]
    classes = {0x1444b1550: h.scratch+0x1b000, 0x1444b1fe0: h.scratch+0x1c000,
               0x1444b1430: h.scratch+0x1d000}
    objects = dict(zip(classes.values(), (context, settings, account)))
    options, heap, pairs, events, stopped = {}, [0], [], [], []

    def put(destination, value, null_empty=False):
        if not h.scratch <= destination <= h.scratch+0x40000-16: raise ValueError('NID gate string object bound')
        data = (value+'\0').encode('utf-16le')
        if len(data) > 256 or heap[0]+len(data) >= h.scratch+0x2e000: raise ValueError('NID gate string heap bound')
        pointer, count = heap[0], len(data)//2
        if not value and null_empty: pointer, count = 0, 0
        else:
            h.uc.mem_write(pointer, data); heap[0] += (len(data)+15)&~15
        h.uc.mem_write(destination, struct.pack('<QII', pointer, count, count))

    def text(address):
        if not h.scratch <= address <= h.scratch+0x40000-16: raise ValueError('NID gate string object bound')
        pointer, count, capacity = struct.unpack('<QII', bytes(h.uc.mem_read(address, 16)))
        if not 0 <= count <= capacity <= 128: raise ValueError('NID gate string count bound')
        if not count: return ''
        if not h.scratch <= pointer <= h.scratch+0x40000-count*2: raise ValueError('NID gate string data bound')
        data = bytes(h.uc.mem_read(pointer, count*2))
        if data[-2:] != bytes(2): raise ValueError('NID gate string termination')
        return data[:-2].decode('utf-16le')

    def fixture(machine):
        at = machine.reg_read(h.x.UC_X86_REG_RIP)
        a, b, c, d = [machine.reg_read(r) for r in
            (h.x.UC_X86_REG_RCX, h.x.UC_X86_REG_RDX, h.x.UC_X86_REG_R8, h.x.UC_X86_REG_R9)]
        result = 0
        if at in classes: result = classes[at]; events.append(['class', hex(at)])
        elif at == 0x1416b0660:
            if a not in objects: raise ValueError('NID gate lazy class receiver differs')
            machine.mem_write(a+0x110, struct.pack('<Q', objects[a])); events.append(['initialize', a])
        elif at == 0x141426950:
            offset = h.image.offset(b-h.image.pe.base); data = h.raw[offset:offset+128]
            if b'\0' not in data: raise ValueError('NID gate ASCII literal bound')
            put(a, data.split(b'\0')[0].decode('ascii')); result = a
        elif at == 0x14455a0a0:
            if a != context or text(b) != 'authWebViewUrl' or c != rbp-0xc8:
                raise ValueError('NID URL getter binding differs')
            put(c, 'fixture-url'); result = int(options['found']); events.append(['lookup', 'authWebViewUrl'])
        elif at in (0x144528390, 0x144531850):
            if a != context: raise ValueError('NID account predicate receiver differs')
            result = options['state'] if at == 0x144528390 else int(options['ready'])
            events.append(['state' if at == 0x144528390 else 'ready', result])
        elif at in (0x14452b620, 0x14452ab90):
            expected = context if at == 0x14452b620 else account
            dest = rbp+0x370 if at == 0x14452b620 else rbp+0x380
            if a != expected or b != dest: raise ValueError('NID account getter binding differs')
            key = 'playerId' if at == 0x14452b620 else 'joinedCountryCode'
            put(b, '' if options['empty_sdk'] else 'fixture-'+key); result = b; events.append(['getter', key])
        elif at in (0x1414632f0, 0x1415134c0):
            if a != rbp+0x450 or d != 0: raise ValueError('NID account map binding differs')
            key, value = struct.unpack('<QQ', bytes(machine.mem_read(c, 16)))
            pairs.append([text(key), text(value)])
        elif at == 0x141483080:
            if not h.scratch+0x20000 <= a < heap[0]: raise ValueError('NID gate free fixture bound')
        else: raise ValueError('Unreviewed NID gate fixture')
        h.finish(result)

    for at in (*classes, 0x1416b0660, 0x141426950, 0x14455a0a0, 0x144528390,
               0x144531850, 0x14452b620, 0x14452ab90, 0x1414632f0, 0x1415134c0, 0x141483080):
        h.add_fixture(at, fixture)

    def stop_hook(machine, address, size, unused):
        if address in options['stops']:
            stopped.append(address); machine.emu_stop()
    # Observe branch destinations before executing error construction / next stage.
    import unicorn as uc_module
    h.uc.hook_add(uc_module.UC_HOOK_CODE, stop_hook)

    def reset(poison, lazy):
        heap[0] = h.scratch+0x20000; pairs.clear(); events.clear(); stopped.clear()
        h.uc.mem_write(rbp-0x200, bytes([poison])*0xa00)
        for class_address, obj in objects.items():
            h.uc.mem_write(class_address+0x110, struct.pack('<Q', 0 if lazy else obj))
        for register, value in ((h.x.UC_X86_REG_RSP, rbp-0x100), (h.x.UC_X86_REG_RBP, rbp),
                (h.x.UC_X86_REG_R12, 0), (h.x.UC_X86_REG_R15, context)):
            h.uc.reg_write(register, value)

    def run(begin, stops):
        options['stops'] = stops
        h.uc.emu_start(begin, 0, count=10000)
        if len(stopped) != 1: raise ValueError('NID gate instruction budget exhausted')
        return stopped[0]

    def canaries(poison):
        if bytes(h.uc.mem_read(rbp-0x200, 16)) != bytes([poison])*16 or bytes(h.uc.mem_read(rbp+0x7f0, 16)) != bytes([poison])*16:
            raise ValueError('NID gate canaries changed')

    gate_cases = []
    for poison, found, count, lazy in itertools.product((0, 0x55, 0xaa, 0xff), (False, True),
            (-0x80000000, -1, 0, 1, 2, 16, 0x7fffffff), (False, True)):
        reset(poison, lazy); options['found'] = found
        h.uc.mem_write(settings+0xa0, struct.pack('<i', count))
        stop = run(0x1450e3d24, {0x1450e3d89, 0x1450e3edd, 0x1450e4058})
        expected = 0x1450e3d89 if not found else (0x1450e3edd if count <= 1 else 0x1450e4058)
        if stop != expected: raise ValueError('NID availability gate differs')
        initializations = sum(e[0] == 'initialize' for e in events)
        if initializations != int(lazy)*(1+int(found)): raise ValueError('NID lazy class gates differ')
        canaries(poison)
        gate_cases.append(dict(poison=poison, url_lookup_success=found, client_id_count=count,
            lazy_class=lazy, stop=hex(stop), events=events.copy(), canaries_unchanged=True))

    account_cases = []
    for poison, count, state, ready, empty_sdk, lazy in itertools.product((0, 0x55, 0xaa, 0xff),
            (0, 1, 2, 16), (0, 1, 100, 255), (False, True), (False, True), (False, True)):
        reset(poison, lazy); options.update(state=state, ready=ready, empty_sdk=empty_sdk)
        token = 'n'*(count-1) if count else ''
        put(context+0xa0, token, null_empty=count == 0)
        put(account+0x78, '' if empty_sdk else 'fixture-sdk-token')
        run(0x1450e48aa, {0x1450e4a95})
        fallback = count <= 1 and ready and state in (0, 100)
        expected = [['accessToken', token]] if count > 1 else []
        if fallback:
            expected = [['playerId', '' if empty_sdk else 'fixture-playerId'],
                ['joinedCountryCode', '' if empty_sdk else 'fixture-joinedCountryCode'],
                ['accessToken', '' if empty_sdk else 'fixture-sdk-token']]
        if pairs != expected: raise ValueError('NID account fields differ')
        if sum(e[0] == 'ready' for e in events) != int(count <= 1): raise ValueError('NID account predicate short circuit differs')
        if sum(e[0] == 'getter' for e in events) != int(fallback)*2: raise ValueError('NID account getter short circuit differs')
        canaries(poison)
        account_cases.append(dict(poison=poison, nid_token_count=count, state=state, ready=ready,
            empty_sdk=empty_sdk, lazy_class=lazy, pairs=pairs.copy(), events=events.copy(), canaries_unchanged=True))
    return dict(schema=1, source=str(h.source), source_sha256=h.sha, evidence=h.evidence,
        gate_cases=gate_cases, account_cases=account_cases, native_execution=True, network_ready=False,
        dependencies={name: hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
            ('replay-nid-gates-11316.py', 'native-request-harness-11316.py', 'build-native-entry-code.py',
             'extract-native-enums.py', 'build-object-zero-init-code.py')},
        limits=['Native gate dispatch stops before error construction or base-pair assembly; getter success is a fixture, not URL validation.',
            'Class getters/initialization, context predicates, player/country getters, FString storage/free and map insertion are fixtures.',
            'No real accounts, tokens, URL encoding, browser callbacks, logging path or authentication execute.'])


if __name__ == '__main__':
    report = replay()
    audit = load('nid_gate_save', HERE/'audit-client-release.py')
    path = audit.save_snapshot(Path('F:/PhoneExit Resources/Vampir/code-clues/nid-gates-11316'), report)
    print(json.dumps(dict(report=str(path), gates=len(report['gate_cases']), accounts=len(report['account_cases']))))
