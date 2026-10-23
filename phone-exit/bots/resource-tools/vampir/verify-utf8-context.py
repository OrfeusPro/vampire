"""Bounded native UTF-16/UTF-8 length, conversion and scalar encoder checks."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def vectors():
    result = []
    for text in ('', 'a', '\x00', 'A\x00B', '\x7f\u0080\u07ff\u0800', 'Ж界', '🙂',
                 '\ud7ff\ue000\ufffd', '\U00010000\U0010ffff', 'Ж🙂Z',
                 'a'*15, 'a'*16, 'a'*127, 'a'*128, 'é'*80):
        encoded = text.encode('utf-16le')
        result.append((encoded, [c.encode('utf-8') for c in text]))
    # Explicit expectations for malformed UTF-16 and the client's noncharacter policy.
    for units, parts in (([0xd800], [b'?']), ([0xdc00], [b'?']),
                         ([0xd800, 65], [b'?', b'A']), ([0xd800, 0xd800], [b'?', b'?']),
                         ([0xdc00, 0xd800], [b'?', b'?']), ([0xfffe, 0xffff], [b'?', b'?']),
                         ([0xd800, 0xdc00, 0xdfff], [b'\xf0\x90\x80\x80', b'?'])):
        result.append((struct.pack('<'+'H'*len(units), *units), parts))
    return result


def verify(context, root):
    bindings = context['bindings']
    length, convert, encoder, writer = [int(bindings[k], 16) for k in ('length', 'convert', 'encoder', 'string-writer')]
    leaf = context['encoder_leaf']
    data = bytes.fromhex(leaf['bytes'])
    if leaf['size'] != len(data) or len(data) > 512 or hashlib.sha256(data).hexdigest() != leaf['sha256']:
        raise ValueError('Encoder leaf bounds or SHA differ')
    h = load('update-native-harness').make_harness(context, context['exports'],
        {length, convert}, leaves={encoder: data.hex()}, root=root)
    native = load('build-native-entry-code')
    rows = load('update-bindings').rows
    if any(r['call'] for r in rows(native, h.image, length)):
        raise ValueError('Length helper has an unreviewed call')
    conversion_calls = [r['direct_target'] for r in rows(native, h.image, convert) if r['call']]
    writer_calls = [r['direct_target'] for r in rows(native, h.image, writer) if r['call']]
    if conversion_calls != [encoder, encoder] or any(writer_calls.count(a) != 1 for a in (length, convert)):
        raise ValueError('String/conversion helper links differ')
    cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    cs.detail = True
    instructions = list(cs.disasm(data, encoder))
    if not instructions or instructions[-1].mnemonic != 'ret':
        raise ValueError('Encoder leaf has no bounded return')
    addresses = {r.address for r in instructions}
    for ins in instructions:
        if ins.group(native.capstone.CS_GRP_CALL):
            raise ValueError('Encoder leaf has an unreviewed call')
        if ins.group(native.capstone.CS_GRP_JUMP):
            if len(ins.operands) != 1 or ins.operands[0].type != native.X86_OP_IMM or ins.operands[0].imm not in addresses:
                raise ValueError('Encoder leaf has an external branch')
    source, output, pointer, capacity = [h.scratch+n for n in (0x1000, 0x4000, 0x7000, 0x7100)]

    def run(address, a, b=0, c=0, d=0):
        for reg, value in ((h.x.UC_X86_REG_RDX, b), (h.x.UC_X86_REG_R8, c), (h.x.UC_X86_REG_R9, d)):
            h.uc.reg_write(reg, value)
        h.uc.reg_write(h.x.UC_X86_REG_RBX, 0xfedcba9876543210)
        result = h.call(address, a, budget=100000)
        if (h.uc.reg_read(h.x.UC_X86_REG_RBX), h.uc.reg_read(h.x.UC_X86_REG_RSP)) != (
                0xfedcba9876543210, h.scratch+0x38008):
            raise ValueError('UTF-8 helper ABI differs')
        return result

    def check_output(expected, cap):
        if bytes(h.uc.mem_read(output-16, 16)) != b'\xa5'*16:
            raise ValueError('UTF-8 prefix canary changed')
        actual = bytes(h.uc.mem_read(output, 1024))
        if actual != expected+b'\x5a'*(1024-len(expected)) or len(expected) > cap:
            raise ValueError('UTF-8 output or capacity guard differs')

    cases = []
    for number, (raw, parts) in enumerate(vectors()):
        h.uc.mem_write(source-16, b'\xa5'*16+raw+b'\x5a'*16)
        required = len(b''.join(parts))
        if run(length, 0, source, len(raw)//2) != required:
            raise ValueError('Native UTF-8 length differs')
        for cap in sorted({0, 1, 2, 3, 4, max(0, required-1), required, required+1}):
            h.uc.mem_write(output-16, b'\xa5'*16+b'\x5a'*1024)
            expected = b''
            for part in parts:
                if len(expected)+len(part) > cap:
                    break
                expected += part
            returned = run(convert, output, cap, source, len(raw)//2)
            success = cap >= required
            if returned != (output+required if success else 0):
                raise ValueError('UTF-8 conversion return differs')
            check_output(expected, cap)
            if bytes(h.uc.mem_read(source-16, len(raw)+32)) != b'\xa5'*16+raw+b'\x5a'*16:
                raise ValueError('UTF-16 source changed')
            cases.append(dict(vector=number, units=len(raw)//2, capacity=cap, required=required,
                              output_hex=expected.hex(), success=success, guards=True))
    # Direct scalar leaf: replacement, capacity, pointer and remaining-count behavior.
    scalars = (0, 0x7f, 0x80, 0x7ff, 0x800, 0xd7ff, 0xd800, 0xdfff, 0xe000,
               0xfffd, 0xfffe, 0xffff, 0x10000, 0x10ffff, 0x110000, 0xffffffff)
    scalar_cases = []
    for scalar in scalars:
        expected = (b'?' if scalar >= 0x110000 or 0xd800 <= scalar <= 0xdfff or scalar in (0xfffe, 0xffff)
                    else chr(scalar).encode('utf-8'))
        for cap in range(5):
            h.uc.mem_write(output-16, b'\xa5'*16+b'\x5a'*1024)
            h.uc.mem_write(pointer, struct.pack('<Q', output))
            h.uc.mem_write(capacity, struct.pack('<I', cap))
            success = cap >= len(expected)
            result = run(encoder, scalar, pointer, capacity) & 255
            written = expected if success else b''
            if result != int(success) or bytes(h.uc.mem_read(pointer, 8)) != struct.pack('<Q', output+len(written)):
                raise ValueError('Scalar encoder result/pointer differs')
            if bytes(h.uc.mem_read(capacity, 4)) != struct.pack('<I', cap-len(written)):
                raise ValueError('Scalar encoder capacity differs')
            check_output(written, cap)
            scalar_cases.append(dict(scalar=scalar, capacity=cap, output_hex=written.hex(), success=success, guards=True))
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native',
        bindings=bindings, evidence=h.evidence, encoder_leaf=leaf, cases=cases, scalar_cases=scalar_cases,
        tools={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
               ('verify-utf8-context.py', 'update-native-harness.py', 'update-bindings.py', 'build-native-entry-code.py')},
        runtime=load('update-native-harness').runtime_inputs(), network_used=False, profile_activated=False,
        limits=['Native length/conversion/encoder only; whole string writer and archive methods not executed.',
                'String writer links verified statically. No preparation, framing, network, auth or server proof.',
                'Explicit UTF-16 counts, positive/zero capacity <=1024, bounded vectors; not arbitrary buffer validation.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    context = json.loads(args.context.read_text('utf-8'))
    report = verify(context, args.root)
    report['context_sha256'] = hashlib.sha256(args.context.read_bytes()).hexdigest()
    target = load('research-workflow').snapshot(args.root, 'native-utf8-checks', report)
    print(json.dumps(dict(report=str(target), cases=len(report['cases']), scalar_cases=len(report['scalar_cases']))))
