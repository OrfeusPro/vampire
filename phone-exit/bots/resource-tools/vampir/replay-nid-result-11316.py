"""Current OnResult validation/adoption caller with explicit synthetic dependencies."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT, BEGIN, END = 0x1450f3e40, 0x1450f40da, 0x1450f4bc4
STOPS = {0x1450f4119:'missing_resultCode', 0x1450f4278:'empty_resultCode',
    0x1450f4d0e:'invalid_or_nonzero_result', 0x1450f4d01:'auth_type_gate',
    0x1450f4458:'empty_accessToken', 0x1450f4610:'empty_channelKey',
    0x1450f4762:'unknown_channel', 0x1450f48ba:'empty_netmarbleId',
    0x1450f4a11:'empty_joinedCountryCode', END:'adoption_calls_reached'}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def replay(root=None,native_primitives=False):
    source_audit = load('nid_result_bindings',HERE/'audit-nid-result-11316.py')
    prior = source_audit.audit(root=root)
    harness = load('nid_result_harness',HERE/'native-request-harness-11316.py')
    exports = {source_audit.EXPORT:source_audit.EXPORT_SHA,
        'run-1740fcc91625':'f2cdd2d5e37669d223dbbf74217780bed1c64090827b75d3b62c78d99f7dce38'}
    functions,leaves={ROOT,0x1414266a0},{}
    if native_primitives:
        primitives=load('nid_actual_primitives',HERE/'nid-primitives-11316.py')
        exports[primitives.EXPORT]=primitives.EXPORT_SHA
        functions.update((0x1415e4460,0x144531900))
        leaves=primitives.leaves(root or Path(prior['source']).parents[2])
    h = harness.make_harness(exports,functions,leaves=leaves,root=root)
    import unicorn
    rbp, owner, settings, cls, rows = [h.scratch+n for n in (0x10000,0x18000,0x19000,0x1a000,0x1b000)]
    names = {int(r['global_address'],16):r['text'] for r in prior['bindings']}
    options, heap, events, lookups, outcome = {}, [0], [], [], [None]

    def allocate(size):
        if not 0 < size <= 1024 or heap[0]+size >= h.scratch+0x30000: raise ValueError('NID result allocation bound')
        pointer = heap[0]; heap[0] += (size+15)&~15
        return pointer

    def put(destination, value):
        if not (h.scratch <= destination <= h.scratch+0x40000-16 or destination in names):
            raise ValueError('NID result string destination bound')
        data = (value+'\0').encode('utf-16le'); pointer = allocate(len(data))
        h.uc.mem_write(pointer,data); h.uc.mem_write(destination,struct.pack('<QII',pointer,len(data)//2,len(data)//2))

    def text(destination):
        if not h.scratch <= destination <= h.scratch+0x40000-16: raise ValueError('NID result FString object bound')
        pointer,count,capacity = struct.unpack('<QII',bytes(h.uc.mem_read(destination,16)))
        if not 0 <= count <= capacity <= 512: raise ValueError('NID result FString counts')
        if not count: return ''
        if not h.scratch <= pointer <= h.scratch+0x40000-count*2: raise ValueError('NID result FString data bound')
        data = bytes(h.uc.mem_read(pointer,count*2))
        if data[-2:] != bytes(2): raise ValueError('NID result FString termination')
        return data[:-2].decode('utf-16le')

    def fixture(machine):
        at = machine.reg_read(h.x.UC_X86_REG_RIP)
        a,b,c = [machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX,h.x.UC_X86_REG_RDX,h.x.UC_X86_REG_R8)]
        result = 0
        if at == 0x141425d60: pass # Explicit hash fixture; lookup uses descriptor identity.
        elif at == 0x14143d950:
            if a != rbp+0x170 or c not in names: raise ValueError('NID result map lookup binding differs')
            key = names[c]; lookups.append(key); result = options['indices'].get(key,0xffffffff)
        elif at == 0x1415e4460:
            if a != rbp-0xcc: raise ValueError('NID result integer output binding differs')
            machine.mem_write(a,struct.pack('<i',options['parsed_value'])); result = int(options['parse_ok'])
            events.append(dict(kind='integer_fixture',ok=options['parse_ok'],value=options['parsed_value']))
        elif at == 0x141436ed0:
            if not h.scratch <= a <= h.scratch+0x40000-16 or not 1 <= b <= 512:
                raise ValueError('NID result copy allocation bound')
            machine.mem_write(a,struct.pack('<Q',allocate(b*2))); machine.mem_write(a+12,struct.pack('<I',b)); result=a
        elif at == 0x144531900:
            if a != rbp-0xd0: raise ValueError('NID result channel output binding differs')
            machine.mem_write(a,bytes([options['channel']])); result=a
            events.append(dict(kind='channel_fixture',value=options['channel']))
        elif at == 0x1444b1550:
            machine.mem_write(cls+0x110,struct.pack('<Q',settings)); result=cls
        elif at in (0x144550d80,0x1445523c0,0x144552e10):
            if a != settings: raise ValueError('NID result adoption receiver differs')
            value=text(b); event=dict(kind='settings_capture',target=hex(at),value=value)
            if at == 0x1445523c0:
                if c & 255 != 1: raise ValueError('NID result ID mode differs')
                event['mode']=c & 255
            events.append(event)
        elif at == 0x144551210:
            if a != settings: raise ValueError('NID result channel receiver differs')
            events.append(dict(kind='channel_capture',value=b & 255))
        elif at == 0x14142a250:
            if a != settings+0xb0 or c > 128 or not h.scratch <= b <= h.scratch+0x40000-(c+1)*2:
                raise ValueError('NID result country binding differs')
            value=bytes(machine.mem_read(b,c*2)).decode('utf-16le')
            events.append(dict(kind='country_capture',value=value))
        else: raise ValueError('Unreviewed NID result fixture')
        h.finish(result)
    for at in (0x141425d60,0x14143d950,0x1415e4460,0x141436ed0,0x144531900,
               0x1444b1550,0x144550d80,0x1445523c0,0x144552e10,0x144551210,0x14142a250):
        if native_primitives and at in (0x1415e4460,0x144531900): continue
        h.add_fixture(at,fixture)
    primitive_evidence,primitive_cases={},{}
    if native_primitives:
        primitive_evidence,verify_crt=primitives.install(h,events)
        primitive_cases=primitives.standalone(h,put,text,heap,events)

    def stop_hook(machine,address,size,user):
        if address in STOPS: outcome[0]=STOPS[address]; machine.emu_stop()
    def invalid_memory(machine,access,address,size,value,user):
        if address < 4096:
            outcome[0]='unmapped_null_access'
            events.append(dict(kind='unmapped_null_access',address=address,size=size,
                instruction=hex(machine.reg_read(h.x.UC_X86_REG_RIP))))
        return False
    h.uc.hook_add(unicorn.UC_HOOK_CODE,stop_hook)
    h.uc.hook_add(unicorn.UC_HOOK_MEM_INVALID,invalid_memory)
    fields=dict(resultCode='0',accessToken='access-fixture',refreshToken='refresh-fixture',
        channelKey='mailUserKey',netmarbleId='user-fixture',joinedCountryCode='UA')
    fixtures=[dict(name='complete',fields=fields)]
    for key in fields:
        fixtures.extend([dict(name='missing_'+key,fields={k:v for k,v in fields.items() if k != key}),
                         dict(name='empty_'+key,fields={**fields,key:''})])
    fixtures.extend([dict(name='parse_failure',fields={**fields,'resultCode':'bad'},parse_ok=False),
        dict(name='nonzero_result',fields={**fields,'resultCode':'200'},parsed_value=200),
        dict(name='unknown_channel',fields={**fields,'channelKey':'unknown'} if native_primitives else fields,channel=0)])
    fixtures.extend(dict(name='auth_type_'+str(mode),fields=fields,auth_type=mode)
        for mode in (*range(256),0x100,0x80000000,0xffffffff))
    if native_primitives:
        for name,status,channel,expected in (
                ('prefix_zero_upper_channel','0abc','MAILUSERKEY','adoption_calls_reached'),
                ('nonzero_prefix','1abc','mailUserKey','invalid_or_nonzero_result'),
                ('empty_numeric','+','mailUserKey','invalid_or_nonzero_result'),
                ('trailing_channel_space','0','mailUserKey ','unknown_channel'),
                ('leading_channel_space','0',' mailUserKey','unknown_channel'),
                ('unknown_channel_name','0','unknown','unknown_channel')):
            fixtures.append(dict(name=name,fields={**fields,'resultCode':status,'channelKey':channel},
                expected_outcome=expected))
    cases=[]
    for poison in (0,0x55,0xaa,0xff):
        for case in fixtures:
            heap[0]=h.scratch+0x20000; events.clear(); lookups.clear(); outcome[0]=None
            h.uc.mem_write(rbp-0x180,bytes([poison])*0x480)
            options.clear()
            options.update(parse_ok=case.get('parse_ok',True),parsed_value=case.get('parsed_value',0),
                channel=case.get('channel',20),auth_type=case.get('auth_type',0),
                indices={key:n for n,key in enumerate(case['fields'])})
            for address,key in names.items(): put(address,key)
            for key,n in options['indices'].items(): put(rows+n*40+16,case['fields'][key])
            h.uc.mem_write(rbp+0x170,struct.pack('<Q',rows))
            h.uc.mem_write(owner+0x150,struct.pack('<I',options['auth_type']))
            empty=h.scratch+0x1e000; put(empty,'')
            empty_pointer=struct.unpack('<Q',bytes(h.uc.mem_read(empty,8)))[0]
            for name,value in dict(RSP=rbp-0x100,RBP=rbp,R15=owner,RDI=empty_pointer,RSI=0,R12=0,RBX=0).items():
                h.uc.reg_write(getattr(h.x,'UC_X86_REG_'+name),value)
            try: h.uc.emu_start(BEGIN,0,count=10000)
            except unicorn.UcError:
                if outcome[0] != 'unmapped_null_access': raise
            if outcome[0] is None: raise ValueError('NID result instruction budget: '+case['name'])
            expected='adoption_calls_reached'
            if case['name']=='missing_resultCode': expected='missing_resultCode'
            elif case['name'].startswith('missing_'): expected='unmapped_null_access'
            elif case['name'].startswith('empty_') and case['name'] != 'empty_refreshToken': expected=case['name']
            elif case['name'] in ('parse_failure','nonzero_result'): expected='invalid_or_nonzero_result'
            elif options['auth_type'] & 0xfffffffa: expected='auth_type_gate'
            elif not options['channel']: expected='unknown_channel'
            expected=case.get('expected_outcome',expected)
            if outcome[0] != expected: raise ValueError('NID result outcome differs: '+repr((case['name'],outcome[0],expected)))
            captures=[e for e in events if e['kind'] in ('settings_capture','country_capture','channel_capture')]
            if expected=='adoption_calls_reached':
                actual=[(e['kind'],e['value']) for e in captures]
                wanted=[('settings_capture',case['fields']['accessToken']),('country_capture',case['fields']['joinedCountryCode']),
                    ('settings_capture',case['fields']['netmarbleId']),('channel_capture',options['channel']),
                    ('settings_capture',case['fields']['refreshToken'])]
                if actual != wanted: raise ValueError('NID result adoption argument order differs')
            elif captures: raise ValueError('NID rejected result reached adoption')
            if bytes(h.uc.mem_read(rbp-0x180,16)) != bytes([poison])*16 or bytes(h.uc.mem_read(rbp+0x2f0,16)) != bytes([poison])*16:
                raise ValueError('NID result stack canaries changed')
            cases.append(dict(name=case['name'],poison=poison,outcome=outcome[0],
                inputs={k:options[k] for k in (('auth_type',) if native_primitives else ('parse_ok','parsed_value','channel','auth_type'))},
                fields=case['fields'],lookups=lookups.copy(),events=events.copy(),canaries_unchanged=True))
    if native_primitives: verify_crt()
    dependencies=('replay-nid-result-11316.py','audit-nid-result-11316.py','native-request-harness-11316.py',
        'build-native-entry-code.py','extract-native-enums.py','build-object-zero-init-code.py')
    if native_primitives: dependencies+=('nid-primitives-11316.py','research-workflow.py')
    return dict(schema=1,source=str(h.source),source_sha256=h.sha,evidence=h.evidence,
        start=hex(BEGIN),stop=hex(END),cases=cases,native_execution=True,network_ready=False,
        primitive_evidence=primitive_evidence,primitive_cases=primitive_cases,native_primitives=native_primitives,
        dependencies={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in dependencies},
        limits=['Actual current OnResult caller slice and whole FString copy execute; query/service acquisition before entry is bypassed.',
            ('Actual numeric/channel helpers and compare execute; CRT calls use recorded local Windows library; channel global storage uses source-checked literals.'
             if native_primitives else 'Integer/channel returns are fixtures; numeric syntax and channel semantics not verified.'),
            'Hash/map lookup, allocation/memcpy, class getter and adoption settings/country assignment are fixtures/captures.',
            'Null accesses reflect the synthetic missing-row map contract, not an observed live-game crash.',
            'No actual account/token, setters/persistence, post-adoption callbacks, browser, full authentication or Android parity verified.'])


if __name__=='__main__':
    report=replay(); audit=load('nid_result_snapshot',HERE/'audit-client-release.py')
    path=audit.save_snapshot(Path('F:/PhoneExit Resources/Vampir/code-clues/nid-result-11316'),report)
    print(json.dumps(dict(report=str(path),cases=len(report['cases']))))
