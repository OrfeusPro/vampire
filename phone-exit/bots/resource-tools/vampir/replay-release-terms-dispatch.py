"""Whole terms dispatcher and queued thunk, with explicit offline fixtures.

Allocation, scheduler ownership, callable storage getter and final consumer are
fixtures. This does not execute the HTTP parser, terms UI or SDK creation.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
SHA = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
DISPATCH, THUNK = 0x144580990, 0x1445742c0
EXPORTS = (
    ('run-18d567ce0cd6', '9b91484b0423a1b99725da19226112bbd4e8987f1cc8c79a4645698fdec0c764'),
    ('run-61bf93179385', '21adce1460632974a791d1e957058596d17bcb6ec04e336e3488686be04bef4c'),
)


def replay():
    spec = importlib.util.spec_from_file_location('terms_dispatch_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    events, queued = [], []
    h = None

    def fixture(at):
        def invoke(uc):
            x = h.x
            a, b, c = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
            result = 0
            if at == 0x14148fc40:
                if (a, b) != (0x28, 8): raise ValueError('Unexpected closure allocation')
                uc.mem_write(closure, b'\0' * 0x28)
                result = closure
            elif at == 0x141409e10:
                target = struct.unpack('<Q', bytes(uc.mem_read(b, 8)))[0]
                storage = struct.unpack('<Q', bytes(uc.mem_read(b + 16, 8)))[0]
                if (a, target, storage) != (1, THUNK, closure): raise ValueError('Unexpected queue descriptor')
                queued.append((target, storage + 8))
            elif at == 0x144532750:
                events.append(dict(kind='storage', address=a))
                result = callable_context
            elif at == 0x145604f00:
                events.append(dict(kind='consumer', context=a, state=uc.mem_read(b, 1)[0],
                                   pair=bytes(uc.mem_read(c, 16)).hex()))
            else:
                raise ValueError('Unknown dispatch fixture')
            sp = uc.reg_read(x.UC_X86_REG_RSP)
            uc.reg_write(x.UC_X86_REG_RAX, result)
            uc.reg_write(x.UC_X86_REG_RIP, struct.unpack('<Q', bytes(uc.mem_read(sp, 8)))[0])
            uc.reg_write(x.UC_X86_REG_RSP, sp + 8)
        return invoke

    fixtures = {a: fixture(a) for a in (0x14148fc40, 0x141409e10, 0x144532750, 0x145604f00)}
    h = archive.make_harness(extra_addresses=(DISPATCH, THUNK), fixtures=fixtures)
    evidence = []
    for run, digest in EXPORTS:
        path = h.comparison / 'details' / run / 'details.json'
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != digest: raise ValueError('Dispatch export changed')
        report = json.loads(payload)
        if report['new_source_sha256'] != SHA: raise ValueError('Dispatch source mismatch')
        for function in report['functions']:
            if not function['decompilation_completed']: raise ValueError('Incomplete dispatch export')
            for row in function['instructions']:
                offset = h.image.offset(int(row['address'], 16) - h.image.pe.base)
                code = bytes.fromhex(row['bytes'])
                if h.raw[offset:offset + len(code)] != code: raise ValueError('Dispatch instruction changed')
        evidence.append(dict(path=str(path), sha256=digest))
    content, pair, response, control, closure, external, table, callable_context = [
        h.scratch + n for n in (0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x11000)]
    h.uc.mem_write(0x14b5662e0, b'\0')  # Logging disabled; formatting is outside this claim.
    h.uc.mem_write(table + 8, struct.pack('<Q', 0x144532750))
    cases = []
    for state in (0, 1, 2, 3, 4, 255):
        for bound in (False, True):
            for heap_storage in (False, True):
                for shared in (False, True):
                    for code in (0, 0x1ca86d0):
                        events.clear()
                        queued.clear()
                        h.uc.mem_write(content, b'\0' * 0x80)
                        h.uc.mem_write(content + 0x20, struct.pack('<Q', 0x145604f00 if bound else 0))
                        h.uc.mem_write(content + 0x30, struct.pack('<Q', external if heap_storage else 0))
                        h.uc.mem_write(content + 0x40, struct.pack('<Q', table))
                        h.uc.mem_write(external, struct.pack('<Q', table))
                        h.uc.mem_write(content + 0x60, b'\1')
                        h.uc.mem_write(control, struct.pack('<QII', 0, 4, 1))
                        original = bytearray(b'\xa5' * 64)
                        struct.pack_into('<I', original, 12, code)
                        h.uc.mem_write(response, bytes(original))
                        pair_bytes = struct.pack('<QQ', response, control if shared else 0)
                        h.uc.mem_write(pair, pair_bytes)
                        h.call(DISPATCH, content, state, pair)
                        if queued != [(THUNK, closure + 8)] or events:
                            raise ValueError('Dispatch invoked consumer before scheduled thunk')
                        if h.uc.mem_read(content + 0x60, 1) != b'\1': raise ValueError('Premature UI reset')
                        retained = struct.unpack('<I', bytes(h.uc.mem_read(control + 8, 4)))[0]
                        if retained != (5 if shared else 4): raise ValueError('Queued shared reference differs')
                        h.call(*queued[0])
                        expected = []
                        if bound:
                            expected = [dict(kind='storage', address=external if heap_storage else content + 0x40),
                                        dict(kind='consumer', context=callable_context, state=state, pair=pair_bytes.hex())]
                        if events != expected: raise ValueError('Queued result forwarding differs')
                        visible = h.uc.mem_read(content + 0x60, 1)[0]
                        if visible != (0 if state in (2, 3) else 1): raise ValueError('Unexpected UI reset')
                        if bytes(h.uc.mem_read(response, 64)) != bytes(original): raise ValueError('Result object changed')
                        if bytes(h.uc.mem_read(pair, 16)) != pair_bytes: raise ValueError('Input pair changed')
                        if struct.unpack('<I', bytes(h.uc.mem_read(control + 8, 4)))[0] != retained:
                            raise ValueError('Thunk unexpectedly released queued ownership')
                        cases.append(dict(state=state, bound=bound, heap_storage=heap_storage,
                                          shared=shared, result_code=code, visible=visible,
                                          forwarded=bound, retained_references=int(shared)))
    return dict(source_sha256=SHA, method='bounded_native', functions=[hex(DISPATCH), hex(THUNK)],
                evidence=evidence, cases=cases,
                fixtures=['allocation succeeds', 'scheduler retains closure until explicit thunk call',
                          'callable storage getter', 'consumer capture', 'logging disabled'],
                limits=['HTTP parser and actual UI/consumer not executed',
                        'queue destruction, ref release and concurrent lifetime not executed',
                        'synthetic result bytes; no live consent or SDK sign-up'])


if __name__ == '__main__':
    report = replay()
    payload = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')
    digest = hashlib.sha256(payload).hexdigest()
    output = Path('F:/PhoneExit Resources/Vampir/code-clues/release-terms-dispatch') / digest / 'manifest.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and output.read_bytes() != payload: raise ValueError('Replay output collision')
    output.write_bytes(payload)
    print(json.dumps(dict(report=str(output), sha256=digest, cases=len(report['cases']))))
