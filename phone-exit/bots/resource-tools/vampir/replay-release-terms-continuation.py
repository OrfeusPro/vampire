"""Current terms callback -> real virtual bridges -> first-player handoff.

Whole callback/closures/classifier execute. UI, SDK, service acquisition and
manager bookkeeping are explicit fixtures; no live terms or sign-up occur.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
SHA = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
EXPORTS = (
    ('run-3380a52fff6d', '7b0307a30a6cc0b33c1149c956e12a0c822fa8f54a6b4299fbd07c429ad518aa'),
    ('run-3a0991b1f1c8', '20a5532389041914f37cfc5236a9c9a50facdc0697d2aca5888f03f97e85e8b4'),
    ('run-c558937a4554', 'b3c2261d213515546d75e43e53b4521a2130815a106a854c6a9b9efb7ea54750'),
    ('run-57ea578ebe47', 'c281575496f53eda31722eb828dfe6c8125bb600a4e268c92e44a5ae4b5537b3'),
)
CALLBACK = 0x145604f00


def load(name):
    spec = importlib.util.spec_from_file_location('terms_' + name.replace('-', '_'), HERE / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def replay():
    events, fixtures, state = [], {}, {}
    h = None
    def capture(address):
        def invoke(uc):
            x = h.x
            a, b, c = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
            result = 0
            if address == 0x1456151f0:
                events.append(dict(kind='log', owner=a, pair=b, step=c & 255))
            elif address == 0x1444b22a0:
                result = service_holder
            elif address == 0x1416b0790:
                if a != service_holder: raise ValueError('Unexpected service holder')
                # Explicit null-CDO fixture: initializer leaves it null.
            elif address == 0x144479cb0:
                if a != sdk + 0x90: raise ValueError('Unexpected idpInfo container')
                result = state['idp_count']
            elif address == 0x14561b940:
                events.append(dict(kind='sign_up_handoff', owner=a, channel=b & 255, step=c & 255))
            elif address == 0x1445fad80:
                events.append(dict(kind='tracked_lookup'))
                result = 0  # Already tracked; insertion/growth path not executed.
            elif address == 0x14561ace0:
                events.append(dict(kind='retry_terms', owner=a, list_address=hex(b), flag=c & 255))
            elif address == 0x145609600:
                uc.mem_write(b, b'\0' * 16)
                result = b
                events.append(dict(kind='error_text', pair=c))
            elif address == 0x141426c10:
                uc.mem_write(a, b'\0' * 16)
                result = a
            elif address == 0x14561b2b0:
                events.append(dict(kind='message', selector=b & 255))
            else:
                raise ValueError('Unknown terms fixture')
            sp = uc.reg_read(x.UC_X86_REG_RSP)
            uc.reg_write(x.UC_X86_REG_RAX, result)
            uc.reg_write(x.UC_X86_REG_RIP, struct.unpack('<Q', bytes(uc.mem_read(sp, 8)))[0])
            uc.reg_write(x.UC_X86_REG_RSP, sp + 8)
        return invoke
    for at in (0x1456151f0, 0x1444b22a0, 0x1416b0790, 0x144479cb0, 0x14561b940,
               0x1445fad80, 0x14561ace0, 0x145609600, 0x141426c10, 0x14561b2b0):
        fixtures[at] = capture(at)
    addresses = (CALLBACK, 0x14560b130, 0x145605cf0, 0x14560aff0, 0x145606690, 0x144532190)
    h = load('replay-release-archive-input').make_harness(extra_addresses=addresses, fixtures=fixtures)
    evidence, functions = [], {}
    for name, sha in EXPORTS:
        path = h.comparison / 'details' / name / 'details.json'
        if hashlib.sha256(path.read_bytes()).hexdigest() != sha: raise ValueError('Terms export changed')
        report = json.loads(path.read_text('utf-8'))
        if report['new_source_sha256'] != SHA: raise ValueError('Terms source mismatch')
        evidence.append(dict(path=str(path), sha256=sha))
        for f in report['functions']:
            if not f['decompilation_completed']: raise ValueError('Incomplete terms export')
            functions[f['address']] = f
            for row in f['instructions']:
                at, code = int(row['address'], 16), bytes.fromhex(row['bytes'])
                offset = h.image.offset(at - h.image.pe.base)
                if h.raw[offset:offset + len(code)] != code: raise ValueError('Terms instruction changed')
    for table, target in ((0x14990d430, 0x14560b130), (0x14990d498, 0x14560aff0)):
        off = h.image.offset(table - h.image.pe.base)
        if struct.unpack_from('<Q', h.raw, off + 0x60)[0] != target: raise ValueError('Terms virtual binding changed')
        page = table & ~4095
        if not any(lo <= page <= hi for lo, hi, _ in h.uc.mem_regions()):
            h.uc.mem_map(page, 4096)
            source = h.image.offset(page - h.image.pe.base)
            h.uc.mem_write(page, h.raw[source:source + 4096])
    leaf = 0x141a2d1b0
    code = bytes.fromhex('8b410cc3')
    off = h.image.offset(leaf - h.image.pe.base)
    if h.raw[off:off + len(code)] != code: raise ValueError('Terms result getter changed')
    page = leaf & ~4095
    if not any(lo <= page <= hi for lo, hi, _ in h.uc.mem_regions()): h.uc.mem_map(page, 4096)
    h.uc.mem_write(leaf, code)
    h.ranges.append((leaf, leaf + len(code)))
    storage, owner, control, pair, response, success_delegate, error_delegate, service_holder, sdk, manager = [
        h.scratch + v for v in (0x1000, 0x2000, 0x3000, 0x4000, 0x4800, 0x5000, 0x6000, 0x10000, 0x11000, 0x12000)]
    h.uc.mem_write(0x14b5e8ec0, struct.pack('<Q', manager))
    h.uc.mem_write(success_delegate, struct.pack('<Q', 0x14990d430))
    h.uc.mem_write(error_delegate, struct.pack('<Q', 0x14990d498))
    profiles = [(False, 0, 0), (True, 100, 0), (True, 100, 1),
                (True, 33, 0), (True, 200, 0), (True, 0, 0)]
    cases = []
    for present, channel, idp_count in profiles:
        state['idp_count'] = idp_count
        h.uc.mem_write(service_holder + 0x110, struct.pack('<Q', sdk if present else 0))
        h.uc.mem_write(sdk + 0x88, bytes([channel]))
        for ui_state in (0, 1, 2, 3):
            for bound in (False, True):
                for result_code in (0, 0x1ca06be):
                    events.clear()
                    h.uc.mem_write(storage, struct.pack('<QQ', owner, control))
                    h.uc.mem_write(control, struct.pack('<QII', 0, 4, 1))
                    h.uc.mem_write(pair, struct.pack('<QQ', response, 0))
                    h.uc.mem_write(response + 0xc, struct.pack('<I', result_code))
                    h.uc.mem_write(owner + 0xa8, struct.pack('<QI', success_delegate if bound else 0, int(bound)))
                    h.uc.mem_write(owner + 0xb8, struct.pack('<QI', error_delegate if bound else 0, int(bound)))
                    for obj in (success_delegate, error_delegate):
                        h.uc.mem_write(obj + 0x18, struct.pack('<QQ', owner, control))
                    h.call(CALLBACK, storage, ui_state, pair)
                    expected = ['log']
                    if bound and ui_state == 2: expected += ['sign_up_handoff', 'tracked_lookup']
                    if bound and ui_state == 3:
                        expected += ['retry_terms'] if result_code == 0x1ca06be else ['error_text', 'message']
                    if [e['kind'] for e in events] != expected: raise ValueError('Terms continuation differs')
                    if events[0] != dict(kind='log', owner=owner, pair=pair, step=7): raise ValueError('Terms log changed')
                    if bound and ui_state == 2:
                        guest = not present or (channel == 100 and idp_count == 0)
                        target = dict(kind='sign_up_handoff', owner=owner, channel=100 if guest else 33, step=12 if guest else 13)
                        if events[1] != target: raise ValueError('Guest/Netmarble choice differs')
                    if expected[-1] == 'message' and events[-1]['selector'] != 20: raise ValueError('Terms error selector changed')
                    count = struct.unpack('<I', bytes(h.uc.mem_read(control + 8, 4)))[0]
                    if count != 4: raise ValueError('Terms owner count unbalanced')
                    cases.append(dict(sdk_present=present, previous_channel=channel, idp_count=idp_count,
                        ui_state=ui_state, bound=bound, result_code=result_code, events=list(events), owner_count=count))
    for label, own, ctrl, count in (('no-control', owner, 0, 4), ('expired', owner, control, 0), ('no-owner', 0, control, 4)):
        events.clear()
        h.uc.mem_write(storage, struct.pack('<QQ', own, ctrl))
        h.uc.mem_write(control, struct.pack('<QII', 0, count, 1))
        h.call(CALLBACK, storage, 2, pair)
        if events or struct.unpack('<I', bytes(h.uc.mem_read(control + 8, 4)))[0] != count:
            raise ValueError('Terms owner gate failed')
        cases.append(dict(owner_gate=label, events=[]))
    return dict(schema=1, source=str(h.source), source_sha256=SHA, callback=hex(CALLBACK),
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), evidence=evidence,
        dependencies={n + '.py': hashlib.sha256((HERE / (n + '.py')).read_bytes()).hexdigest() for n in (
            'replay-release-archive-input', 'replay-release-nested-read-thunk', 'build-native-entry-code',
            'build-object-zero-init-code', 'extract-native-enums', 'audit-client-release')},
        functions=list(functions.values()), cases=cases, network_requests=0,
        limits=['Whole terms callback, both native virtual bridges and closures, classifier and result getter execute.',
                'Service holder/CDO, idpInfo count, SDK handoff, UI/logger, tracked lookup are fixtures/captures.',
                'Tracked entry exists; manager insertion/growth, final destructors and races are not covered.',
                'Raw UI states are synthetic, not proof of actual agreement completion or server state.',
                'No terms UI, HTTP, SDK SignUp or character creation is performed.'])


if __name__ == '__main__':
    report = replay()
    audit = load('audit-client-release')
    target = audit.save_snapshot(load('build-native-entry-code').ROOT / 'code-clues/release-terms-continuation', report)
    print(json.dumps(dict(report=str(target), sha256=audit.sha256(target), cases=len(report['cases']), network_requests=0)))
