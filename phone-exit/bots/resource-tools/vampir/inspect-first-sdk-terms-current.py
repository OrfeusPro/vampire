"""Current Terms GET contracts and bounded NO DATA/error native composition.

HTTP/JSON/allocator/string/service/scheduler and final continuation are fixtures.
No process, network, UI acceptance, SDK creation or runtime admission.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/first-sdk-terms-current.json'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
RECIPE = 'first-sdk-terms-current-v1'
ROLES = {'basic_loader', 'basic_response', 'individual_loader', 'individual_response',
         'dispatcher', 'thunk', 'result_constructor', 'get_impl', 'individual_constructor', 'type_getter',
         'basic_game_wrapper', 'individual_game_wrapper', 'basic_game_callback', 'individual_game_callback'}


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def checked(path, sha, inputs):
    path = Path(path).resolve(); raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha: raise ValueError('Terms input SHA changed: ' + path.name)
    inputs[str(path)] = sha
    return raw


def data(image, address, size):
    at = image.offset(address - image.pe.base)
    if image.offset(address + size - 1 - image.pe.base) != at + size - 1:
        raise ValueError('Terms file-backed range differs')
    return image.data[at:at + size]


def static_contract(context, root, inputs):
    if (context.get('schema') != 1 or context.get('recipe') != RECIPE or context.get('source_sha256') != SOURCE
            or set(context['functions']) != ROLES):
        raise ValueError('Current Terms contract role/source differs')
    native, normalize = load('build-native-entry-code'), load('audit-launcher-shape-11318')
    source = root / 'client-code-snapshots' / SOURCE / 'ProjectRED-Win64-Shipping.exe'
    image = native.Image(checked(source, SOURCE, inputs))
    wanted = {int(at, 16) for at in context['functions'].values()}
    functions = {}
    for run, expected in context['exports'].items():
        path = root / 'ghidra/request-exports' / SOURCE / run / 'details.json'
        exported = json.loads(checked(path, expected, inputs))
        if exported['new_source_sha256'] != SOURCE: raise ValueError('Terms export source differs')
        for f in exported['functions']:
            at = int(f['address'], 16)
            if at not in wanted: continue
            if at in functions or f.get('decompilation_completed') is not True:
                raise ValueError('Terms whole export duplicate/incomplete')
            functions[at] = f
    if set(functions) != wanted: raise ValueError('Terms whole export missing')
    shapes = {at: normalize.normalize_function(native, image, f) for at,f in functions.items()}
    for name, pointer in context['literal_bindings'].items():
        encoding = pointer['encoding']; code = (pointer['text'] + '\0').encode(encoding)
        if data(image, int(pointer['address'],16), len(code)) != code:
            raise ValueError('Terms literal changed: ' + name)
        for role in pointer.get('roles', []):
            if pointer['address'] not in {r['target'] for r in shapes[int(context['functions'][role],16)]['references']}:
                raise ValueError('Terms literal role reference absent: ' + name)
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64); decoder.detail = True
    for label, fragment in context['fragments'].items():
        at, code = int(fragment['address'],16), bytes.fromhex(fragment['bytes'])
        if data(image, at, len(code)) != code: raise ValueError('Terms explicit fragment changed: ' + label)
        rows = list(decoder.disasm(code,at))
        if len(rows) != fragment['instruction_count'] or sum(r.size for r in rows) != len(code):
            raise ValueError('Terms fragment boundaries differ')
        calls = [hex(row.operands[0].imm) for row in rows if row.mnemonic in ('call','jmp') and row.operands[0].type == native.X86_OP_IMM]
        if calls != fragment['calls']: raise ValueError('Terms fragment call targets differ')
    for role, required in context['calls'].items():
        actual = {r['target'] for r in shapes[int(context['functions'][role],16)]['calls']}
        if not set(required) <= actual: raise ValueError('Terms direct-call contract changed: ' + role)
    table = context['type_table']
    ctor_refs = {r['target'] for r in shapes[int(context['functions']['individual_constructor'],16)]['references']}
    if table not in ctor_refs or struct.unpack('<Q',data(image,int(table,16)+0x30,8))[0] != int(context['functions']['type_getter'],16):
        raise ValueError('Terms type virtual binding changed')
    # Bind the caller's actual virtual +30 request, not just a table/name match.
    individual = functions[int(context['functions']['individual_loader'],16)]
    if not any(row['bytes']=='ff5030' for row in individual['instructions']):
        raise ValueError('Terms type virtual call is absent')
    for role, callback in context['callbacks'].items():
        at = int(callback['address'],16); jump = data(image,at,5)
        if jump[0]!=0xe9 or at+5+struct.unpack_from('<i',jump,1)[0]!=int(context['functions'][role],16):
            raise ValueError('Terms callback tail changed')
        loader = 'basic_loader' if role=='basic_response' else 'individual_loader'
        if callback['address'] not in {r['target'] for r in shapes[int(context['functions'][loader],16)]['references']}:
            raise ValueError('Terms response pointer is not from its loader')
    return image, functions, shapes


def replay(context, root, *, compose=False):
    functions = {k:int(v,16) for k,v in context['functions'].items()}
    native_roles = {'basic_response','individual_response','dispatcher','thunk','result_constructor'}
    continuation = json.loads((HERE/'knowledge/native-contexts/first-sdk-continuation-11322.json').read_bytes())
    extra = {int(value,16) for value in continuation['functions'].values()}
    if compose:
        if continuation['source_sha256'] != SOURCE: raise ValueError('Terms composition source differs')
        native_roles.add('basic_game_callback')
    h = load('native-request-harness-11316').make_harness(context['exports'],
        {functions[k] for k in native_roles} | (extra if compose else set()),
        leaves={int(a,16):b for a,b in context['leaves'].items()} | ({int(a,16):b for a,b in continuation['leaves'].items()} if compose else {}),
        root=root,source_sha256=SOURCE,copy_thunk=None)
    uc,x = h.uc,h.x
    fixture = {k:int(v,16) for k,v in context['fixtures'].items()}
    if compose:
        fixture.pop('basic_continuation'); fixture.pop('individual_continuation')
        fixture.update({name:int(continuation['fixtures'][name],16) for name in
            ('log','service_holder','service_acquire','idp_count','sign_up','tracked_lookup','individual_terms')})
        fixture.update(delegate_allocate=0x14142d0f0,delegate_id=0x14142ef60)
    if set(fixture.values()) & {functions[k] for k in native_roles}: raise ValueError('Terms executed native root replaced by fixture')
    content, storage, pair, http, body, literal, svc, settings, observer, external, table, callable_context = [
        h.scratch+n for n in (0x1000,0x2000,0x3000,0x4000,0x5000,0x6000,0x7000,0x8000,0x9000,0xa000,0xb000,0xc000)]
    state,events,queue = {},[],[]
    owner,control,manager = (h.scratch+value for value in (0xd000,0xe000,0xf000))
    def qword(at): return int.from_bytes(uc.mem_read(at,8),'little')
    def allocate(size):
        if size not in (0x18,0x28,0x40): raise ValueError('Terms allocation bound')
        result=state['heap'];state['heap']+=0x100
        if state['heap']>=h.scratch+0x30000: raise ValueError('Terms fixture heap exhausted')
        uc.mem_write(result,b'\0'*size);return result
    def invoke(name):
        def callback(machine):
            a,b,c=[machine.reg_read(reg) for reg in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
            result=0
            if name=='http_body':
                if a!=http:raise ValueError('Terms HTTP fixture receiver')
                result=body
            elif name in ('string_copy','literal'):
                if name=='string_copy':
                    if b!=body:raise ValueError('Terms body-copy fixture input')
                    uc.mem_write(a,struct.pack('<QII',body,9,9))
                else:uc.mem_write(a,struct.pack('<QII',literal,8,8))
                result=a
            elif name=='string_assign':
                uc.mem_write(a,bytes(uc.mem_read(b,16)));result=a
            elif name=='free':pass
            elif name=='json_parse':
                if c!=1:raise ValueError('Terms JSON fixture parse flags')
                uc.mem_write(a,b'\0'*56);state['json']=a;result=a
            elif name in ('json_valid','json_has','json_int'):
                if a!=state['json']:raise ValueError('Terms JSON getter receiver')
                if name=='json_valid':result=int(state['json_valid'])
                elif name=='json_has':
                    if b not in (int(context['keys']['resultCode'],16),int(context['keys']['resultData'],16)):
                        raise ValueError('Terms JSON key differs')
                    result=int(state['keys'])
                else:
                    if b!=int(context['keys']['resultCode'],16):raise ValueError('Terms resultCode getter key')
                    result=state['code']&0xffffffff
            elif name=='http_secondary_success':result=0
            elif name in ('allocate','closure_allocate'):result=allocate(a)
            elif name=='service':result=svc
            elif name=='observer':result=observer
            elif name=='notify':
                if a!=observer or machine.mem_read(b,1)!=b'\1':raise ValueError('Terms observer fixture contract')
                events.append(dict(kind='observer',result=c))
            elif name=='schedule':
                if a!=1 or qword(b)!=functions['thunk']:raise ValueError('Terms queued thunk differs')
                queue.append(qword(b+16)+8)
            elif name=='storage':result=callable_context
            elif name in ('basic_continuation','individual_continuation'):
                events.append(dict(kind='continuation',state=b&255,result=qword(c),context=a))
            elif name in ('http_error_constructor','json_error_constructor'):
                # Only malformed/transport paths use these alternate constructor fixtures.
                uc.mem_write(a,b'\0'*64);uc.mem_write(a,struct.pack('<4I',b,c,machine.reg_read(x.UC_X86_REG_R9),
                    (b+c+machine.reg_read(x.UC_X86_REG_R9))&0xffffffff))
                uc.mem_write(a+0x28,struct.pack('<q',state['status'] if name=='http_error_constructor' else 0));result=a
            elif name=='result_cleanup':pass
            elif name=='log':events.append(dict(kind='game_log',step=c&255))
            elif name=='service_holder':result=svc
            elif name=='service_acquire':
                if a!=svc:raise ValueError('Terms composition service differs')
            elif name=='idp_count':result=0
            elif name=='sign_up':events.append(dict(kind='sign_up',owner=a,channel=b&255,step=c&255))
            elif name=='tracked_lookup':result=0
            elif name=='individual_terms':
                if a!=owner or b!=0x14b5e8368 or c&255:raise ValueError('Terms next-query arguments differ')
                events.append(dict(kind='individual_terms',owner=a))
            elif name=='delegate_allocate':
                if a!=0x28 or b not in (owner+0xa8,owner+0xb8):raise ValueError('Terms delegate allocation differs')
                result=allocate(a);uc.mem_write(b,struct.pack('<QI',result,1))
            elif name=='delegate_id':result=1
            else:raise ValueError('Unknown Terms fixture')
            h.finish(result)
        return callback
    for name,address in fixture.items():h.add_fixture(address,invoke(name))
    uc.mem_write(svc+0x110,struct.pack('<Q',settings));uc.mem_write(settings+0xc8,b'\0')
    uc.mem_write(table+8,struct.pack('<Q',fixture['storage']));uc.mem_write(external,struct.pack('<Q',table))
    uc.mem_write(body,struct.pack('<QII',body+0x100,9,9));uc.mem_write(literal,b'f\0i\0x\0t\0u\0r\0e\0\0\0')
    uc.mem_write(int(context['logging_global'],16),b'\0')
    if compose:
        uc.mem_write(int(continuation['manager_global'],16),struct.pack('<Q',manager))
        uc.mem_write(settings+0x88,b'\x21')
        uc.mem_write(callable_context,struct.pack('<QQ',owner,control))
        uc.mem_write(control,struct.pack('<QII',0,4,1))
    cases=[]
    variants=[('no_data',-1,True,True,200),('sdk_error',1203,True,True,200),
              ('negative_error',-2147483648,True,True,200),('positive_error',2147483647,True,True,200),
              ('bad_json',0,False,True,200),('missing_key',0,True,False,200),('http_error',0,True,True,400)]
    if compose: variants=variants[:1]
    state['heap']=h.scratch+0x10000
    for role in ('basic_response','individual_response'):
        for label,code,valid,keys,status in variants:
            for bound in ((True,) if compose else (False,True)):
                for heap_storage in ((False,) if compose else (False,True)):
                    events.clear();queue.clear();state.update(json_valid=valid,keys=keys,code=code,status=status)
                    if not compose:state['heap']=h.scratch+0x10000
                    adapter=context['continuation_adapters'][role]
                    uc.mem_write(content,b'\0'*0x80);uc.mem_write(content+0x20,struct.pack('<Q',int(adapter,16) if bound else 0))
                    uc.mem_write(content+0x30,struct.pack('<Q',external if heap_storage else 0));uc.mem_write(content+0x40,struct.pack('<Q',table));uc.mem_write(content+0x60,b'\1')
                    uc.mem_write(storage,struct.pack('<Q',content));uc.mem_write(pair,struct.pack('<QQ',http,0))
                    uc.mem_write(http,b'\0'*0x40);uc.mem_write(http+4,struct.pack('<I',0 if status==200 else 1));uc.mem_write(http+0x28,struct.pack('<q',status))
                    uc.reg_write(x.UC_X86_REG_RDX,pair);h.call(functions[role],storage,budget=10000)
                    if len(queue)!=1:raise ValueError('Terms response did not queue one result')
                    queued=queue[0];result=qword(queued+16);ctrl=qword(queued+24);raw=bytes(uc.mem_read(result,64))
                    raw_state=uc.mem_read(queued+8,1)[0];expected_state=2 if label=='no_data' else 3
                    if raw_state!=expected_state:raise ValueError('Terms NO DATA/error state differs')
                    if label in ('no_data','sdk_error','negative_error','positive_error'):
                        kind=0x1bbc if role=='basic_response' else 0x1c20
                        branch=15 if role=='basic_response' and label=='no_data' else 9
                        expected=(kind,0x1ca86d0,branch,kind+0x1ca86d0+branch)
                        if struct.unpack('<4I',raw[:16])!=expected or struct.unpack_from('<q',raw,0x28)[0]!=code:
                            raise ValueError('Real Terms result constructor fields/context differ')
                        if raw[0x20]!=1:raise ValueError('Terms body-present constructor flag differs')
                    if qword(ctrl+8)&0xffffffff!=1:raise ValueError('Terms queue final shared reference differs')
                    h.call(functions['thunk'],queued)
                    continuations=[event for event in events if event['kind']=='continuation']
                    if not compose and len(continuations)!=int(bound):raise ValueError('Terms continuation binding differs')
                    if not compose and bound and continuations[0] != dict(kind='continuation',state=expected_state,result=result,context=callable_context):
                        raise ValueError('Terms continuation received different result/state')
                    if compose:
                        actions=[event for event in events if event['kind'] in ('individual_terms','sign_up')]
                        expected_action=(dict(kind='individual_terms',owner=owner) if role=='basic_response'
                            else dict(kind='sign_up',owner=owner,channel=33,step=13))
                        if actions != [expected_action]:raise ValueError('Terms composed NO DATA action differs')
                        if int.from_bytes(uc.mem_read(control+8,4),'little')!=4:
                            raise ValueError('Terms composed owner count differs')
                    if bytes(uc.mem_read(result,64))!=raw or uc.mem_read(content+0x60,1)!=b'\0':
                        raise ValueError('Terms queued result changed or UI pending flag not cleared')
                    cases.append(dict(role=role,scenario=label,result_code=code,http_status=status,bound=bound,heap_storage=heap_storage,
                        state=raw_state,result_context=struct.unpack_from('<q',raw,0x28)[0],real_result_constructor=label in ('no_data','sdk_error','negative_error','positive_error'),
                        continuation_calls=len(continuations),result_bytes=raw.hex(),
                        composed_actions=actions if compose else []))
    return cases


def verify(context_path=CONTEXT, *, root=ROOT):
    root,context_path=Path(root).resolve(),Path(context_path).resolve();inputs={}
    raw=context_path.read_bytes();context=json.loads(raw);inputs[str(context_path)]=hashlib.sha256(raw).hexdigest()
    image,functions,shapes=static_contract(context,root,inputs)
    cases=replay(context,root)
    composition=replay(context,root,compose=True)
    continuation=context['continuation'];proof=json.loads(checked(Path(continuation['path']),continuation['sha256'],inputs))
    if proof.get('source_sha256')!=SOURCE or proof.get('network_used') is not False:
        raise ValueError('Terms continuation proof source/boundary differs')
    for name in ('inspect-first-sdk-terms-current','native-request-harness-11316','build-native-entry-code','extract-native-enums',
                 'audit-launcher-shape-11318','knowledge-index'):
        path=HERE/(name+'.py');inputs[str(path.resolve())]=digest(path)
    child_context=HERE/'knowledge/native-contexts/first-sdk-continuation-11322.json'
    inputs[str(child_context.resolve())]=digest(child_context)
    for path,sha in inputs.copy().items():checked(Path(path),sha,{})
    if context_path.read_bytes()!=raw:raise ValueError('Terms context changed during native execution')
    return dict(schema=1,recipe=RECIPE,source_sha256=SOURCE,method='bounded_native',inputs=inputs,
        contract_subset_verified=True,native_execution=True,network_used=False,runtime_admitted=False,profile_activated=False,
        functions=[dict(role=role,address=at,instructions=len(shapes[int(at,16)]['shape'])) for role,at in context['functions'].items()],
        requests=dict(method='GET',basic=context['queries']['basic'],filtered=context['queries']['filtered'],individual=context['queries']['individual'],
            individual_type='I',query_inputs='Explicit caller country/locale/platform; observed native OS values not claimed'),
        keys=context['keys'],cases=cases,composition=composition,continuation=continuation,
        limits=['New native cases execute only current Basic/Individual NO DATA and error response branches, real result constructor/dispatcher/thunk.',
            'HTTP body, JSON parse/getters, allocation, strings, service, scheduler, alternate transport/JSON error constructors and final continuation remain fixtures.',
            'Content-bearing zero result parsing/UI, consent, native GET backend, final destruction and lifetime races are not executed.',
            'Two additional composed NO DATA responses execute actual Basic callback/delegate initialization and Individual callback/bridges/classifier through a captured Netmarble33/step13 handoff.',
            'Raw state2 is NO DATA, not accepted consent. Existing current continuation proof is reused by pointer; its 126 scenarios are not rerun.',
            'No SDK SignUp/SignIn, account mutation or runtime admission. The separate runtime loader must enforce exact no_data summaries and all immutable inputs.'])


def verify_report(path, *, root=ROOT, workspace=HERE.parents[3]):
    root,path,workspace=Path(root).resolve(),Path(path).resolve(),Path(workspace).resolve()
    raw=path.read_bytes();sha=hashlib.sha256(raw).hexdigest()
    if path!=root/'code-clues/first-sdk-terms-current-v1'/sha/'manifest.json':raise ValueError('Terms immutable report path differs')
    report=json.loads(raw)
    if (report.get('schema')!=1 or report.get('recipe')!=RECIPE or report.get('source_sha256')!=SOURCE
            or report.get('contract_subset_verified') is not True or report.get('native_execution') is not True
            or report.get('network_used') is not False or report.get('runtime_admitted') is not False
            or len(report.get('cases',[]))!=56 or len(report.get('composition',[]))!=2):raise ValueError('Terms report scope/cases differ')
    context_path=(workspace/'phone-exit/bots/resource-tools/vampir/knowledge/native-contexts/first-sdk-terms-current.json').resolve()
    mandatory={str(context_path),str(Path(__file__).resolve()),
        str((root/'client-code-snapshots'/SOURCE/'ProjectRED-Win64-Shipping.exe').resolve())}
    if not mandatory<=set(report['inputs']):raise ValueError('Terms context/source/checker is not pinned')
    for name,digest_value in report['inputs'].items():
        input_path=Path(name).resolve()
        if not any(input_path.is_relative_to(base) for base in (root,workspace)):raise ValueError('Terms report input outside declared roots')
        checked(input_path,digest_value,{})
    if path.read_bytes()!=raw:raise ValueError('Terms report changed during validation')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT);parser.add_argument('--context',type=Path,default=CONTEXT)
    args=parser.parse_args();report=verify(args.context,root=args.root)
    target=load('audit-client-release').save_snapshot(args.root/'code-clues/first-sdk-terms-current-v1',report)
    print(json.dumps(dict(report=str(target),sha256=digest(target),cases=len(report['cases']),native_execution=True,network_used=False,runtime_admitted=False)))


if __name__=='__main__':main()
