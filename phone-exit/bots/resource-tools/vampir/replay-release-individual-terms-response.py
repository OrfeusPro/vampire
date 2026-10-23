"""Individual nonzero response -> real error constructor -> game continuation.

HTTP/JSON/string/allocator/service/scheduler boundaries are explicit fixtures.
No network, game process, agreement write or SDK sign-up is performed.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
SHA = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
RESPONSE, CTOR, DISPATCH, THUNK = 0x14456b510, 0x144517fd0, 0x144580990, 0x1445742c0
GAME = (0x145604f00, 0x14560b130, 0x145605cf0, 0x14560aff0, 0x145606690, 0x144532190)
EXPORTS = (
    ('run-1b2b935daa62', 'fc36502fde60719b09bcbaef04f5fdb21ae45e078f6f50a906c76815896d957b'),
    ('run-3380a52fff6d', '7b0307a30a6cc0b33c1149c956e12a0c822fa8f54a6b4299fbd07c429ad518aa'),
    ('run-61bf93179385', '21adce1460632974a791d1e957058596d17bcb6ec04e336e3488686be04bef4c'),
    ('run-8c0479e8b8bd', 'c0e9b7937e1d716ecbf03759a5449a60a2f7e4e7fee46fda852643067b4d1cd5'),
    ('run-18d567ce0cd6', '9b91484b0423a1b99725da19226112bbd4e8987f1cc8c79a4645698fdec0c764'),
    ('run-3a0991b1f1c8', '20a5532389041914f37cfc5236a9c9a50facdc0697d2aca5888f03f97e85e8b4'),
    ('run-c558937a4554', 'b3c2261d213515546d75e43e53b4521a2130815a106a854c6a9b9efb7ea54750'),
    ('run-57ea578ebe47', 'c281575496f53eda31722eb828dfe6c8125bb600a4e268c92e44a5ae4b5537b3'),
)


def replay():
    spec = importlib.util.spec_from_file_location('individual_response_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    h = None
    state, events, queue = {}, [], []

    def qword(at): return struct.unpack('<Q', bytes(h.uc.mem_read(at, 8)))[0]

    def fixture(at):
        def invoke(uc):
            x = h.x
            a, b, c = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
            result = 0
            if at == 0x140bd6440:
                if a != http: raise ValueError('Unexpected HTTP object')
                result = body_buffer
            elif at in (0x141426780, 0x141426a30):
                # FString construction is a fixture, including allocation ownership.
                if at == 0x141426780:
                    if b != body_buffer: raise ValueError('Unexpected HTTP body input')
                    data = struct.pack('<QII', body_buffer, state['body_count'], state['body_count'])
                else:
                    data = struct.pack('<QII', literal_buffer, 8, 8)
                uc.mem_write(a, data)
                result = a
            elif at == 0x141441e40:
                uc.mem_write(a, bytes(uc.mem_read(b, 16)))
                result = a
            elif at == 0x141483160:
                if a not in (body_buffer, literal_buffer): raise ValueError('Unexpected string release')
            elif at == 0x1444873b0:
                if c != 1: raise ValueError('Unexpected JSON parse flag')
                uc.mem_write(a, b'\0' * 56)
                state['json_object'] = a
                result = a
            elif at in (0x14447fb90, 0x14447eb10, 0x14447d9a0):
                if a != state['json_object']: raise ValueError('Unexpected JSON object')
                if at == 0x14447fb90:
                    result = 1
                elif at == 0x14447eb10:
                    if b not in (0x14b566760, 0x14b5667a0): raise ValueError('Unexpected JSON key')
                    result = 1
                else:
                    if b != 0x14b566760: raise ValueError('Unexpected resultCode key')
                    result = state['result_code'] & 0xffffffff
            elif at in (0x14690a090, 0x14148fc40):
                if a not in (0x18, 0x28, 0x40): raise ValueError('Unexpected terms allocation')
                result = state['allocation']
                state['allocation'] += 0x100
                uc.mem_write(result, b'\0' * a)
            elif at == 0x1444b2e50:
                result = service_holder
            elif at == 0x144527320:
                result = observer
            elif at == 0x144550280:
                if a != observer or uc.mem_read(b, 1) != b'\1': raise ValueError('Unexpected error notification')
                events.append(dict(kind='observer', result=c))
            elif at == 0x141409e10:
                if a != 1 or qword(b) != THUNK: raise ValueError('Unexpected terms scheduler')
                queue.append(qword(b + 16) + 8)
            elif at == 0x1445326c0:
                events.append(dict(kind='storage', address=a))
                result = callable_context
            elif at == 0x1456151f0:
                events.append(dict(kind='game_log', owner=a, pair=b, step=c & 255,
                                   code=struct.unpack('<I', bytes(uc.mem_read(qword(b) + 12, 4)))[0]))
            elif at == 0x1444b22a0:
                result = game_service_holder
            elif at == 0x144479cb0:
                if a != sdk + 0x90: raise ValueError('Unexpected IDP container')
                result = 1  # Explicit existing Netmarble identity fixture.
            elif at == 0x14561b940:
                events.append(dict(kind='sign_up_handoff', owner=a, channel=b & 255, step=c & 255))
            elif at == 0x1445fad80:
                events.append(dict(kind='tracked_lookup'))
            elif at == 0x145609600:
                uc.mem_write(b, b'\0' * 16)
                result = b
                events.append(dict(kind='error_text'))
            elif at == 0x141426c10:
                uc.mem_write(a, b'\0' * 16)
                result = a
            elif at == 0x14561b2b0:
                events.append(dict(kind='message', selector=b & 255))
            else:
                raise ValueError('Unreviewed individual terms fixture')
            sp = uc.reg_read(x.UC_X86_REG_RSP)
            uc.reg_write(x.UC_X86_REG_RAX, result)
            uc.reg_write(x.UC_X86_REG_RIP, qword(sp))
            uc.reg_write(x.UC_X86_REG_RSP, sp + 8)
        return invoke

    fixtures = {a: fixture(a) for a in (
        0x140bd6440, 0x141426780, 0x141426a30, 0x141441e40, 0x141483160,
        0x1444873b0, 0x14447fb90, 0x14447eb10, 0x14447d9a0,
        0x14690a090, 0x14148fc40, 0x1444b2e50, 0x144527320, 0x144550280,
        0x141409e10, 0x1445326c0, 0x1456151f0, 0x1444b22a0, 0x144479cb0,
        0x14561b940, 0x1445fad80, 0x145609600, 0x141426c10, 0x14561b2b0)}
    h = archive.make_harness(extra_addresses=(RESPONSE, CTOR, DISPATCH, THUNK, *GAME), fixtures=fixtures)
    evidence = []
    for run, digest in EXPORTS:
        path = h.comparison / 'details' / run / 'details.json'
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != digest: raise ValueError('Individual terms export changed')
        report = json.loads(payload)
        if report['new_source_sha256'] != SHA: raise ValueError('Individual terms source mismatch')
        for function in report['functions']:
            if not function['decompilation_completed']: raise ValueError('Incomplete individual terms export')
            for row in function['instructions']:
                offset = h.image.offset(int(row['address'], 16) - h.image.pe.base)
                code = bytes.fromhex(row['bytes'])
                if h.raw[offset:offset + len(code)] != code: raise ValueError('Individual terms instruction changed')
        evidence.append(dict(path=str(path), sha256=digest))
    # Execute the actual HTTP success predicate, whose bound has been reviewed.
    for leaf, hex_bytes in ((0x144532750, '837904000f94c0c3'), (0x141a2d1b0, '8b410cc3'),
                            (0x145608200, '0fb612e9f8ccffff')):
        code = bytes.fromhex(hex_bytes)
        offset = h.image.offset(leaf - h.image.pe.base)
        if h.raw[offset:offset + len(code)] != code: raise ValueError('Result getter changed')
        if not any(lo <= leaf <= hi for lo, hi, _ in h.uc.mem_regions()): h.uc.mem_map(leaf & ~4095, 4096)
        h.uc.mem_write(leaf, code)
        h.ranges.append((leaf, leaf + len(code)))
    for table_address, target in ((0x14990d430, 0x14560b130), (0x14990d498, 0x14560aff0)):
        off = h.image.offset(table_address - h.image.pe.base)
        if struct.unpack_from('<Q', h.raw, off + 0x60)[0] != target: raise ValueError('Game virtual binding changed')
        page = table_address & ~4095
        if not any(lo <= page <= hi for lo, hi, _ in h.uc.mem_regions()):
            h.uc.mem_map(page, 4096)
            source = h.image.offset(page - h.image.pe.base)
            h.uc.mem_write(page, h.raw[source:source + 4096])
    storage, content, http_pair, http, body_buffer, literal_buffer, service_holder, service, observer, external, table, callable_context = [
        h.scratch + n for n in (0x1000, 0x2000, 0x3000, 0x4000, 0x10000, 0x12000,
                                0x14000, 0x15000, 0x16000, 0x17000, 0x18000, 0x19000)]
    owner, owner_control, success_delegate, error_delegate, game_service_holder, sdk, manager = [
        h.scratch + n for n in (0x1a000, 0x1b000, 0x1c000, 0x1d000, 0x30000, 0x31000, 0x32000)]
    h.uc.mem_write(0x14b5e8ec0, struct.pack('<Q', manager))
    h.uc.mem_write(game_service_holder + 0x110, struct.pack('<Q', sdk))
    h.uc.mem_write(sdk + 0x88, bytes([33]))
    h.uc.mem_write(success_delegate, struct.pack('<Q', 0x14990d430))
    h.uc.mem_write(error_delegate, struct.pack('<Q', 0x14990d498))
    h.uc.mem_write(owner + 0xa8, struct.pack('<QI', success_delegate, 1))
    h.uc.mem_write(owner + 0xb8, struct.pack('<QI', error_delegate, 1))
    for obj in (success_delegate, error_delegate, callable_context):
        h.uc.mem_write(obj + (0x18 if obj != callable_context else 0), struct.pack('<QQ', owner, owner_control))
    h.uc.mem_write(0x14b5662e0, b'\0')
    h.uc.mem_write(service_holder + 0x110, struct.pack('<Q', service))
    h.uc.mem_write(service + 0xc8, b'\0')  # Disable constructor logging branch.
    h.uc.mem_write(table + 8, struct.pack('<Q', 0x1445326c0))
    h.uc.mem_write(external, struct.pack('<Q', table))
    cases = []
    for result_code in (-1, 1, 1203, -2147483648, 2147483647):
        for bound in (False, True):
            for heap_storage in (False, True):
                for with_message in (False, True):
                    # Python supplies JSON getter fixtures from the same synthetic body.
                    body = dict(resultCode=result_code, resultData={'terms': {'title': None, 'url': None}})
                    if with_message: body['resultMessage'] = 'synthetic fixture'
                    encoded = json.dumps(body).encode('utf-16le') + b'\0\0'
                    events.clear()
                    queue.clear()
                    state.update(result_code=body['resultCode'], body_count=len(encoded) // 2,
                                 allocation=h.scratch + 0x20000)
                    h.uc.mem_write(h.scratch + 0x7000, b'\0' * 0x2000)
                    h.uc.mem_write(body_buffer, encoded)
                    h.uc.mem_write(literal_buffer, 'fixture\0'.encode('utf-16le'))
                    h.uc.mem_write(owner_control, struct.pack('<QII', 0, 4, 1))
                    h.uc.mem_write(storage, struct.pack('<Q', content))
                    h.uc.mem_write(content, b'\0' * 0x80)
                    h.uc.mem_write(content + 0x20, struct.pack('<Q', 0x145608200 if bound else 0))
                    h.uc.mem_write(content + 0x30, struct.pack('<Q', external if heap_storage else 0))
                    h.uc.mem_write(content + 0x40, struct.pack('<Q', table))
                    h.uc.mem_write(content + 0x60, b'\1')
                    h.uc.mem_write(http, b'\0' * 0x40)
                    h.uc.mem_write(http_pair, struct.pack('<QQ', http, 0))
                    h.call(RESPONSE, storage, http_pair, budget=8192)
                    if len(queue) != 1 or [e['kind'] for e in events] != ['observer']:
                        raise ValueError('Unexpected individual response events')
                    queued = queue[0]
                    result, control = qword(queued + 16), qword(queued + 24)
                    if result != events[0]['result']: raise ValueError('Observer/queue result identity differs')
                    fields = struct.unpack('<4I', bytes(h.uc.mem_read(result, 16)))
                    expected_fields = (0x1c20, 0x1ca86d0, 9, 0x1c20 + 0x1ca86d0 + 9)
                    if fields != expected_fields: raise ValueError('Actual error constructor layout differs')
                    context = struct.unpack('<q', bytes(h.uc.mem_read(result + 0x28, 8)))[0]
                    if context != result_code or h.uc.mem_read(result + 0x20, 1) != b'\1':
                        raise ValueError('Actual error context/body flag differs')
                    ui_state = h.uc.mem_read(queued + 8, 1)[0]
                    if ui_state != (2 if result_code == -1 else 3): raise ValueError('Individual response state differs')
                    if struct.unpack('<I', bytes(h.uc.mem_read(control + 8, 4)))[0] != 1:
                        raise ValueError('Queue must retain final shared reference')
                    original = bytes(h.uc.mem_read(result, 64))
                    h.call(THUNK, queued)
                    if bound:
                        expected = [dict(kind='observer', result=result),
                                    dict(kind='storage', address=external if heap_storage else content + 0x40),
                                    dict(kind='game_log', owner=owner, pair=queued + 16, step=7, code=fields[3])]
                        if ui_state == 2:
                            expected += [dict(kind='sign_up_handoff', owner=owner, channel=33, step=13),
                                         dict(kind='tracked_lookup')]
                        else:
                            expected += [dict(kind='error_text'), dict(kind='message', selector=20)]
                    else: expected = [dict(kind='observer', result=result)]
                    if events != expected:
                        raise ValueError(f'Individual continuation differs: {events!r}; expected {expected!r}')
                    if bytes(h.uc.mem_read(result, 64)) != original:
                        raise ValueError('Original constructed error changed')
                    if h.uc.mem_read(content + 0x60, 1) != b'\0': raise ValueError('UI flag not cleared')
                    if struct.unpack('<I', bytes(h.uc.mem_read(owner_control + 8, 4)))[0] != 4:
                        raise ValueError('Game owner reference balance differs')
                    cases.append(dict(result_code=result_code, context=context, ui_state=ui_state,
                                      aggregate_code=fields[3], bound=bound, heap_storage=heap_storage,
                                      with_message=with_message, body_present=True,
                                      sign_up_handoff=bound and ui_state == 2))
    return dict(source_sha256=SHA, method='bounded_native', evidence=evidence, cases=cases,
                functions=[hex(a) for a in (RESPONSE, CTOR, DISPATCH, THUNK, 0x145608200, *GAME)], network_requests=0,
                fixtures=['HTTP body getter; JSON parser/getters', 'FString construction/copy/release',
                          'allocation succeeds', 'service acquisition and error observer capture',
                          'scheduler retains closure and callable storage getter',
                          'Netmarble SDK identity/service, logging, error text, final SDK handoff capture',
                          'tracked lookup already exists; no insertion/growth'],
                limits=['HTTP success only; malformed JSON, zero code/content/UI and allocation failures not executed',
                        'queue destruction/release, logging and concurrent lifetime not executed',
                        'synthetic responses, no live account or SDK sign-up'])


if __name__ == '__main__':
    report = replay()
    payload = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')
    digest = hashlib.sha256(payload).hexdigest()
    path = Path('F:/PhoneExit Resources/Vampir/code-clues/release-individual-terms-response') / digest / 'manifest.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() != payload: raise ValueError('Response report collision')
    path.write_bytes(payload)
    print(json.dumps(dict(report=str(path), sha256=digest, cases=len(report['cases']))))
