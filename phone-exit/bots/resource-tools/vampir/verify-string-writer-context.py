"""Whole native FString writer with native UTF-8 and explicit allocator/archive fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from importlib.util import spec_from_file_location, module_from_spec

HERE = Path(__file__).resolve().parent


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(context, root):
    bindings = context['bindings']
    writer, length, convert, encoder = [int(bindings[k], 16) for k in
        ('string-writer', 'length', 'convert', 'encoder')]
    leaf = context['encoder_leaf']
    data = bytes.fromhex(leaf['bytes'])
    if len(data) != leaf['size'] or len(data) > 512 or hashlib.sha256(data).hexdigest() != leaf['sha256']:
        raise ValueError('Encoder leaf bounds or SHA differ')
    h = load('update-native-harness').make_harness(context, context['exports'],
        {writer, length, convert}, leaves={encoder: data.hex()}, root=root)
    native = load('build-native-entry-code')
    rows = load('update-bindings').rows
    fixture = context['fixtures']
    if fixture['archive_slot'] != 0x28:
        raise ValueError('Unreviewed archive slot')
    addresses = {k: int(v, 16) for k, v in fixture.items() if k != 'archive_slot'}
    calls = [r for r in rows(native, h.image, writer) if r['call']]
    direct = [r['direct_target'] for r in calls if r['direct_target'] is not None]
    expected = [length, addresses['utf8_allocate'], convert, int(context['helpers']['memcpy'], 16),
                addresses['cpp_allocate'], addresses['cpp_allocate'], int(context['helpers']['memcpy'], 16),
                addresses['utf8_free'], addresses['cpp_free'], addresses['security_check'],
                0x1421fb5e0, 0x1418cbe20]
    if direct != expected:
        raise ValueError('String writer direct calls differ')
    indirect = [r['operands'] for r in calls if r['direct_target'] is None]
    if indirect != ['qword ptr [rip + 0x3eeeb77]', 'qword ptr [rax + 0x28]', 'qword ptr [rip + 0x3eeeaeb]']:
        raise ValueError('String writer indirect calls differ')
    if [r['direct_target'] for r in rows(native, h.image, convert) if r['call']] != [encoder, encoder]:
        raise ValueError('Native UTF-8 converter link differs')
    # Validate the bounded encoder's call/jump closure independently of its bytes hash.
    cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    cs.detail = True
    instructions = list(cs.disasm(data, encoder))
    allowed = {i.address for i in instructions}
    if not instructions or instructions[-1].mnemonic != 'ret':
        raise ValueError('Encoder return missing')
    for ins in instructions:
        if ins.group(native.capstone.CS_GRP_CALL):
            raise ValueError('Unreviewed encoder call')
        if ins.group(native.capstone.CS_GRP_JUMP) and (len(ins.operands) != 1 or
                ins.operands[0].type != native.X86_OP_IMM or ins.operands[0].imm not in allowed):
            raise ValueError('Unreviewed encoder branch')
    source, descriptor, archive, table = [h.scratch+n for n in (0x1000, 0x4000, 0x5000, 0x6000)]
    archive_method = h.scratch+0x7000
    state = {}

    def registers(*names):
        return [h.uc.reg_read(getattr(h.x, 'UC_X86_REG_'+n)) for n in names]

    def allocate(size, kind):
        if not 1 <= size <= 8192 or kind in state['allocated']:
            raise ValueError('Allocation fixture budget differs')
        pointer = h.scratch+(0x8000 if kind == 'utf8' else 0xc000)
        h.uc.mem_write(pointer-16, b'\xa5'*16+b'\x5a'*size+b'\xa6'*16)
        state['allocated'][kind] = (pointer, size)
        return pointer

    def free(pointer, kind, size=None):
        if kind not in state['allocated'] or kind in state['freed']:
            raise ValueError('Unowned or repeated fixture free')
        expected, capacity = state['allocated'][kind]
        if pointer != expected or (size is not None and size != capacity):
            raise ValueError('Free pointer or size differs')
        if (bytes(h.uc.mem_read(pointer-16, 16)), bytes(h.uc.mem_read(pointer+capacity, 16))) != (
                b'\xa5'*16, b'\xa6'*16):
            raise ValueError('Allocation canary changed')
        state['freed'].add(kind)

    def utf8_allocate(machine):
        a, b, count, alignment = registers('RCX', 'RDX', 'R8', 'R9')
        if b != 0 or alignment != 1 or int.from_bytes(h.uc.mem_read(a, 8), 'little') != 0:
            raise ValueError('UTF-8 allocation arguments differ')
        h.uc.mem_write(a, struct.pack('<Q', allocate(count, 'utf8')))
        h.finish()

    def utf8_free(machine):
        free(registers('RCX')[0], 'utf8')
        h.finish()

    def cpp_allocate(machine):
        h.finish(allocate(registers('RCX')[0], 'cpp'))

    def cpp_free(machine):
        a, size = registers('RCX', 'RDX')
        free(a, 'cpp', size)
        h.finish()

    def security(machine):
        cookie_offset = h.image.offset(0x14b271780-h.image.pe.base)
        cookie = int.from_bytes(h.raw[cookie_offset:cookie_offset+8], 'little')
        if registers('RCX')[0] != cookie:
            raise ValueError('Security cookie differs')
        state['security_checks'] += 1
        h.finish(registers('RAX')[0])

    def archive_write(machine):
        receiver, string = registers('RCX', 'RDX')
        if receiver != archive or state['archive_calls'] != 0:
            raise ValueError('Unexpected archive receiver or repeat')
        descriptor_bytes = bytes(h.uc.mem_read(string, 32))
        size, capacity = struct.unpack_from('<QQ', descriptor_bytes, 16)
        pointer = string if capacity <= 15 else int.from_bytes(descriptor_bytes[:8], 'little')
        expected = state['expected']
        if size != len(expected) or size > capacity or bytes(h.uc.mem_read(pointer, size+1)) != expected+b'\0':
            raise ValueError('Archive UTF-8 string or terminator differs')
        if ('utf8' in state['allocated']) != ('utf8' in state['freed']):
            raise ValueError('Temporary UTF-8 buffer not freed before archive')
        state.update(archive_calls=1, cpp_capacity=capacity)
        h.finish(0xabcdef00 | state['archive_result'])

    for name, handler in (('utf8_allocate', utf8_allocate), ('utf8_free', utf8_free),
                          ('cpp_allocate', cpp_allocate), ('cpp_free', cpp_free), ('security_check', security)):
        h.add_fixture(addresses[name], handler)
    h.add_fixture(archive_method, archive_write)
    archive_bytes = struct.pack('<Q', table)+b'\xa6'*120
    h.uc.mem_write(archive, archive_bytes)
    h.uc.mem_write(table+0x28, struct.pack('<Q', archive_method))
    vectors = load('verify-utf8-context').vectors()
    vectors += [(('a'*n).encode('utf-16le'), [b'a']*n) for n in (14, 17, 126, 129, 255, 4095)]
    cases = []
    abi = {name: 0x123456789abcdef0+i for i, name in enumerate(('RBX', 'RSI', 'RDI', 'RBP', 'R12', 'R14', 'R15'))}
    for number, (raw, parts) in enumerate(vectors):
        expected = b''.join(parts).split(b'\0', 1)[0]
        raw += b'\0\0'
        source_bytes = b'\xa5'*16+raw+b'\xa6'*16
        h.uc.mem_write(source-16, source_bytes)
        # Nonzero count is a branch gate; writer scans the first UTF-16 NUL itself.
        for count in sorted({len(raw)//2, 1} | ({0} if number in (0, 3) else set())):
            case_expected = expected if count else b''
            text_descriptor = struct.pack('<QII', source if count else 0, count, len(raw)//2)
            h.uc.mem_write(descriptor-16, b'\xa5'*16+text_descriptor+b'\xa6'*16)
            for result in (0, 1, 0x80, 0xff):
                state.update(allocated={}, freed=set(), expected=case_expected, archive_calls=0,
                             archive_result=result, security_checks=0)
                for name, value in abi.items():
                    h.uc.reg_write(getattr(h.x, 'UC_X86_REG_'+name), value)
                h.uc.reg_write(h.x.UC_X86_REG_RDX, descriptor)
                actual = h.call(writer, archive, budget=2000000)
                if actual != result or state['archive_calls'] != 1 or state['security_checks'] != 1:
                    raise ValueError('Archive return byte or security epilogue differs')
                if set(state['allocated']) != state['freed']:
                    raise ValueError('Allocation not freed')
                if bytes(h.uc.mem_read(source-16, len(source_bytes))) != source_bytes:
                    raise ValueError('Input UTF-16 changed')
                if bytes(h.uc.mem_read(descriptor-16, 48)) != b'\xa5'*16+text_descriptor+b'\xa6'*16:
                    raise ValueError('FString descriptor changed')
                if bytes(h.uc.mem_read(archive, len(archive_bytes))) != archive_bytes:
                    raise ValueError('Archive fixture changed')
                if any(h.uc.reg_read(getattr(h.x, 'UC_X86_REG_'+name)) != value for name, value in abi.items()):
                    raise ValueError('Writer nonvolatile register changed')
                if h.uc.reg_read(h.x.UC_X86_REG_RSP) != h.scratch+0x38008:
                    raise ValueError('Writer stack differs')
                cases.append(dict(vector=number, count=count, utf8_bytes=len(case_expected), archive_result=result,
                                  allocations={k:v[1] for k,v in state['allocated'].items()},
                                  cpp_capacity=state['cpp_capacity'], guards=True))
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native', bindings=bindings,
        evidence=h.evidence, cases=cases, network_used=False, profile_activated=False,
        tools={n:hashlib.sha256((HERE/n).read_bytes()).hexdigest() for n in
            ('verify-string-writer-context.py', 'verify-utf8-context.py', 'update-native-harness.py',
             'update-bindings.py', 'build-native-entry-code.py')},
        runtime=load('update-native-harness').runtime_inputs(),
        limits=['Whole string writer and native UTF-8 helpers; allocator/free/security/archive are explicit fixtures.',
                'Zero count with null pointer, or positive count and terminated storage; nonzero count/null pointer excluded.',
                'No archive wire encoding, allocation failure, OS, auth, network, preparation or result reader.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    report = verify(json.loads(args.context.read_text('utf-8')), args.root)
    report['context_sha256'] = hashlib.sha256(args.context.read_bytes()).hexdigest()
    target = load('research-workflow').snapshot(args.root, 'native-string-writer-checks', report)
    print(json.dumps(dict(report=str(target), cases=len(report['cases']))))
