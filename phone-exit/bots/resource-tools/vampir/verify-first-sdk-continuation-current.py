"""Current native Fetch/terms continuations; HTTP and SDK writes stay outside."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/first-sdk-continuation-11322.json'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
RECIPE = 'first-sdk-continuation-current-v1'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify(context_path=CONTEXT, *, root=ROOT):
    context_path, root = Path(context_path).resolve(), Path(root).resolve()
    raw_context = context_path.read_bytes()
    context = json.loads(raw_context)
    if (context.get('schema') != 1 or context.get('recipe') != RECIPE
            or context.get('source_sha256') != SOURCE):
        raise ValueError('Current first SDK continuation source differs')
    functions = {name: int(value, 16) for name, value in context['functions'].items()}
    expected_roles = {'fetch_callback', 'terms_callback', 'success_bridge', 'error_bridge',
                      'success_closure', 'error_closure', 'channel_classifier'}
    if set(functions) != expected_roles or len(set(functions.values())) != 7:
        raise ValueError('First SDK native role set differs')
    leaves = {int(address, 16): code for address, code in context['leaves'].items()}
    if sorted(leaves.values()) != sorted(('837904000f94c0c3', '8b410cc3', '488b4128c3')):
        raise ValueError('First SDK result getter bytes differ')
    h = load('native-request-harness-11316').make_harness(context['exports'], set(functions.values()),
        leaves=leaves, root=root, source_sha256=SOURCE, copy_thunk=None)
    fixture_names = {'log', 'sign_in', 'basic_terms', 'error_text', 'fstring', 'message',
                     'service_holder', 'service_acquire', 'idp_count', 'sign_up', 'tracked_lookup', 'individual_terms'}
    if set(context['fixtures']) != fixture_names:
        raise ValueError('First SDK fixture declarations differ')
    fixtures = {name: int(value, 16) for name, value in context['fixtures'].items()}
    if len(set(fixtures.values())) != len(fixtures) or set(fixtures.values()) & (set(functions.values()) | set(leaves)):
        raise ValueError('Native roots cannot be replaced by continuation fixtures')
    uc, x = h.uc, h.x
    storage, owner, control, pair, response, success, failure, service, sdk, manager = [
        h.scratch + offset for offset in (0x1000, 0x2000, 0x3000, 0x4000, 0x4800,
                                         0x5000, 0x6000, 0x10000, 0x11000, 0x12000)]
    events, state = [], {}

    def fixture(name):
        def invoke(machine):
            a, b, c = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
            result = 0
            if name == 'log':
                events.append(dict(kind='log', owner=a, pair=b, step=c & 255))
            elif name in ('sign_in', 'sign_up'):
                events.append(dict(kind=name, owner=a, channel=b & 255, step=c & 255))
            elif name in ('basic_terms', 'individual_terms'):
                events.append(dict(kind=name, owner=a))
            elif name in ('error_text', 'fstring'):
                destination = b if name == 'error_text' else a
                if not h.scratch <= destination <= h.scratch + 0x3fff0:
                    raise ValueError('Continuation FString fixture bound')
                machine.mem_write(destination, b'\0' * 16)
                result = destination
                if name == 'error_text': events.append(dict(kind=name, pair=c))
            elif name == 'message':
                events.append(dict(kind=name, selector=b & 255))
            elif name == 'service_holder':
                result = service
            elif name == 'service_acquire':
                if a != service: raise ValueError('First SDK service holder differs')
            elif name == 'idp_count':
                if a != sdk + 0x90: raise ValueError('First SDK IDP receiver differs')
                result = state['idp_count']
            elif name == 'tracked_lookup':
                events.append(dict(kind=name))
            else:
                raise ValueError('Unknown first SDK fixture')
            h.finish(result)
        return invoke

    for name, address in fixtures.items(): h.add_fixture(address, fixture(name))
    tables = {name: int(address, 16) for name, address in context['tables'].items()}
    if set(tables) != {'success', 'error'}: raise ValueError('First SDK delegate tables differ')
    for name, target_name in (('success', 'success_bridge'), ('error', 'error_bridge')):
        table, expected = tables[name], functions[target_name]
        actual = struct.unpack_from('<Q', h.raw, h.image.offset(table - h.image.pe.base) + 0x60)[0]
        if actual != expected: raise ValueError('First SDK native virtual binding differs')
        page = table & ~4095
        if not any(low <= page <= high for low, high, _ in uc.mem_regions()):
            uc.mem_map(page, 4096)
            offset = h.image.offset(page - h.image.pe.base)
            uc.mem_write(page, h.raw[offset:offset + 4096])
    uc.mem_write(success, struct.pack('<Q', tables['success']))
    uc.mem_write(failure, struct.pack('<Q', tables['error']))
    global_manager = int(context['manager_global'], 16)
    uc.mem_write(global_manager, struct.pack('<Q', manager))

    def call(address, a, b, c=0):
        uc.reg_write(x.UC_X86_REG_RDX, b)
        uc.reg_write(x.UC_X86_REG_R8, c)
        return h.call(address, a)

    def owner_state(own=owner, ctrl=control, count=4):
        events.clear()
        uc.mem_write(storage, struct.pack('<QQ', own, ctrl))
        uc.mem_write(control, struct.pack('<QII', 0, count, 1))
        uc.mem_write(pair, struct.pack('<QQ', response, 0))
        uc.mem_write(response, b'\0' * 64)

    def balanced(count=4):
        if struct.unpack('<I', bytes(uc.mem_read(control + 8, 4)))[0] != count:
            raise ValueError('First SDK owner reference count differs')

    fetch_cases, terms_cases = [], []
    for ok in (False, True):
        for code in (0, 30050026, 30050027, 30050012):
            for result_context in (1202, 1203, 1204):
                owner_state()
                uc.mem_write(response + 4, struct.pack('<I', 0 if ok else 1))
                uc.mem_write(response + 12, struct.pack('<I', code))
                uc.mem_write(response + 40, struct.pack('<Q', result_context))
                call(functions['fetch_callback'], storage, pair)
                expected = ['log', 'sign_in'] if ok else (
                    ['log', 'basic_terms'] if (code, result_context) == (30050027, 1203)
                    else ['log', 'error_text', 'message'])
                if [event['kind'] for event in events] != expected:
                    raise ValueError('Current Fetch challenge gate differs')
                if events[0] != dict(kind='log', owner=owner, pair=pair, step=11):
                    raise ValueError('Current Fetch step differs')
                if ok and events[1] != dict(kind='sign_in', owner=owner, channel=33, step=15):
                    raise ValueError('Current Fetch SignIn handoff differs')
                if expected[-1] == 'message' and events[-1]['selector'] != 6:
                    raise ValueError('Current Fetch error selector differs')
                balanced()
                fetch_cases.append(dict(success=ok, code=code, context=result_context, events=list(events)))
    profiles = ((False, 0, 0), (True, 100, 0), (True, 100, 1),
                (True, 33, 0), (True, 200, 0), (True, 0, 0))
    for present, channel, idp in profiles:
        state['idp_count'] = idp
        uc.mem_write(service + 0x110, struct.pack('<Q', sdk if present else 0))
        uc.mem_write(sdk + 0x88, bytes([channel]))
        for ui_state in (0, 1, 2, 3):
            for bound in (False, True):
                for code in (0, 0x1ca06be):
                    owner_state()
                    uc.mem_write(response + 12, struct.pack('<I', code))
                    for offset, delegate in ((0xa8, success), (0xb8, failure)):
                        uc.mem_write(owner + offset, struct.pack('<QI', delegate if bound else 0, int(bound)))
                        uc.mem_write(delegate + 0x18, struct.pack('<QQ', owner, control))
                    call(functions['terms_callback'], storage, ui_state, pair)
                    expected = ['log']
                    if bound and ui_state == 2: expected += ['sign_up', 'tracked_lookup']
                    if bound and ui_state == 3:
                        expected += ['individual_terms'] if code == 0x1ca06be else ['error_text', 'message']
                    if [event['kind'] for event in events] != expected:
                        raise ValueError('Current terms continuation differs')
                    if events[0] != dict(kind='log', owner=owner, pair=pair, step=7):
                        raise ValueError('Current terms step differs')
                    if bound and ui_state == 2:
                        guest = not present or (channel == 100 and idp == 0)
                        if events[1] != dict(kind='sign_up', owner=owner, channel=100 if guest else 33,
                                              step=12 if guest else 13):
                            raise ValueError('Current terms channel selection differs')
                    if expected[-1] == 'message' and events[-1]['selector'] != 20:
                        raise ValueError('Current terms error selector differs')
                    balanced()
                    terms_cases.append(dict(sdk_present=present, channel=channel, idp_count=idp,
                        ui_state=ui_state, bound=bound, code=code, events=list(events)))
    for target_name, cases in (('fetch_callback', fetch_cases), ('terms_callback', terms_cases)):
        for label, own, ctrl, count in (('no-control', owner, 0, 4), ('expired', owner, control, 0), ('no-owner', 0, control, 4)):
            owner_state(own, ctrl, count)
            if target_name == 'fetch_callback': call(functions[target_name], storage, pair)
            else: call(functions[target_name], storage, 2, pair)
            if events: raise ValueError('Expired current SDK owner produced an action')
            balanced(count)
            cases.append(dict(owner_gate=label, events=[]))
    inputs = {str(context_path): hashlib.sha256(raw_context).hexdigest(), str(Path(__file__).resolve()): digest(__file__),
              str(h.source.resolve()): SOURCE}
    for name in ('native-request-harness-11316', 'build-native-entry-code', 'extract-native-enums', 'audit-client-release'):
        path = HERE / (name + '.py'); inputs[str(path)] = digest(path)
    for item in h.evidence: inputs[item['path']] = item['sha256']
    if any(digest(path) != expected for path, expected in inputs.items()):
        raise ValueError('First SDK continuation inputs changed during verification')
    report = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, inputs=inputs,
        context=dict(path=str(context_path), sha256=inputs[str(context_path)]),
        fetch_cases=fetch_cases, terms_cases=terms_cases, functions=context['functions'],
        native_execution=True, network_used=False, runtime_admitted=False,
        limits=['Whole current Fetch callback, terms callback, two virtual bridges, two closures, classifier and three result getters execute.',
                'HTTP/JSON response construction and Basic/Individual Terms parsing are outside this native composition.',
                'Raw UI states and results are synthetic; state 2 is not proof of consent or a live NO DATA response.',
                'Service acquisition, IDP count, existing tracked entry, logging, UI, Terms and SDK handoffs are fixtures or captures.',
                'No SDK profile, character or session is created; unknown destructors, allocation/growth and lifetime races are not executed.'])
    path = load('audit-client-release').save_snapshot(root / 'code-clues/first-sdk-continuation-current-v1', report)
    return dict(report=str(path), sha256=digest(path), fetch_cases=len(fetch_cases), terms_cases=len(terms_cases))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, default=CONTEXT)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(verify(args.context, root=args.root)))
