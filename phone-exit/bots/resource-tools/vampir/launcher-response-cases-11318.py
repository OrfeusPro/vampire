"""Bounded response callback branches composed with native dispatch/cleanup."""
import hashlib
import importlib.util
from pathlib import Path


def run_cases(h,owner,result,control,payload,state,events):
    uc,x,b=h.uc,h.x,h.scratch
    weak,closure,response,pair,context,sdk,buffer=[b+n for n in
        (0x7000,0x8000,0x9000,0xa000,0xb000,0xc000,0x1b000)]
    current={};constructed=[]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def get(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def put(at,n,size=8):uc.mem_write(at,int(n).to_bytes(size,'little'))
    def empty(at):uc.mem_write(at,bytes(16))
    def finish_empty(machine):empty(reg('RCX'));h.finish(reg('RCX'))
    def noop(machine):h.finish()
    def alloc(machine):
        size=reg('RCX')
        if size not in (0x40,0x18):raise ValueError('Response result allocation differs')
        at=result if size==0x40 else control
        uc.mem_write(at,bytes(size));h.finish(at)
    def construct(kind):
        def callback(machine):
            if reg('RCX')!=result or reg('RDX')!=0:raise ValueError('Result constructor arguments differ')
            code=get(reg('RSP')+0x30) if kind in ('error','transport') else reg('R8')
            if kind=='invalid-json':
                capture=get(reg('RSP')+0x30)
                if get(capture)!=response or get(capture+8):raise ValueError('Invalid-JSON result lost original HTTP response')
            constructed.append(dict(kind=kind,category=reg('R8'),stage=reg('R9'),code=code))
            uc.mem_write(result,b'\x5a'*0x40);h.finish(result)
        return callback
    def json_init(machine):uc.mem_write(reg('RCX'),bytes(56));h.finish(reg('RCX'))
    def has(machine):
        key=reg('RDX')
        value=current['has_error'] if key==0x14b563da0 else current['has_result'] if key==0x14b563df0 else False
        h.finish(int(value))
    def error_pair(machine):
        if reg('R8')!=0x14b563da0:raise ValueError('Response error field key differs')
        empty(reg('RDX'));h.finish(reg('RDX'))
    def error_text(machine):
        text=str(current['error_code']);uc.mem_write(buffer,(text+'\0').encode('utf-16le'))
        put(reg('RDX'),buffer);put(reg('RDX')+8,len(text)+1,4);put(reg('RDX')+12,len(text)+1,4)
        h.finish(reg('RDX'))
    def wtoi(machine):
        if reg('RCX')!=buffer:raise ValueError('Response numeric conversion input differs')
        h.finish(current['error_code']&0xffffffff)
    def free(machine):
        if reg('RCX')!=buffer:raise ValueError('Response freed unadmitted string')
        h.finish()
    def token_text(machine):
        if reg('R8')!=0x14b563df0:raise ValueError('Token result key differs')
        empty(reg('RDX'));h.finish(reg('RDX'))
    def object_result(machine):uc.mem_write(reg('RDX'),bytes(56));h.finish(reg('RDX'))
    def old_token(machine):empty(reg('RDX'));h.finish(reg('RDX'))
    fixtures={0x146908e50:alloc,0x144517740:construct('transport'),0x144517150:construct('invalid-json'),
        0x144517460:construct('error'),0x144516c00:construct('token'),
        0x144531be0:lambda machine:h.finish(current['primary']),
        0x141639c20:lambda machine:h.finish(current['fallback']),
        0x140bd6440:lambda machine:h.finish(context),0x1414266a0:finish_empty,
        0x144486840:json_init,0x14180e560:lambda machine:h.finish(current['status']),
        0x14447f020:lambda machine:h.finish(current['json_valid']),0x14447dfa0:has,
        0x14447d8f0:error_pair,0x14447d4e0:error_text,0x14447d460:token_text,
        0x141426b30:finish_empty,0x141426950:finish_empty,0x141483080:free,
        0x144476600:noop,0x14447d210:object_result,0x14452b920:old_token,
        0x1444c2010:lambda machine:h.finish(sdk),0x144543150:noop,
        0x144553070:noop,0x144538320:lambda machine:h.finish(context),0x141445be0:noop,
        0x14452b3a0:lambda machine:h.finish(context),0x14452b910:lambda machine:h.finish(context),
        0x14454f840:noop,0x14452bc90:lambda machine:h.finish(context),0x144541190:noop}
    for at,fn in fixtures.items():h.add_fixture(at,fn)
    # Verify the import before redirecting its IAT slot to a bounded fixture.
    spec=importlib.util.spec_from_file_location('response_imports',Path(__file__).with_name('build-object-zero-init-code.py'))
    imports=importlib.util.module_from_spec(spec);spec.loader.exec_module(imports)
    identity=imports.import_at(h.raw,h.image,0x14899bbb0)
    if (identity['dll'].lower(),identity['name'])!=('api-ms-win-crt-convert-l1-1-0.dll','_wtoi'):
        raise ValueError('Response conversion import identity differs')
    h.add_fixture(b+0x2e000,wtoi);put(0x14899bbb0,b+0x2e000)
    scenarios=[dict(name=name,lifetime=name) for name in ('shutdown','weak-missing','weak-expired','owner-missing')]
    scenarios.extend([dict(name='no-response',primary=False,fallback=False),
        dict(name='fallback-response',primary=False,fallback=True),dict(name='invalid-json',json_valid=False)])
    for status in (199,200,206,207,400):
        for error in (None,0,7):
            for has_result in (False,True):
                scenarios.append(dict(name='fields',status=status,has_error=error is not None,
                    error_code=error or 0,has_result=has_result))
    rows=[]
    for route,entry,callback in (('token',0x1444cc4b0,0x1444dec90),('sign-in',0x1444d3a30,0x1444def50)):
        for config in scenarios:
            current.clear();current.update(primary=True,fallback=False,status=200,json_valid=True,
                has_error=False,error_code=0,has_result=False,lifetime='ready');current.update(config)
            early=current['lifetime']!='ready'
            category='none' if early else 'transport' if not(current['primary'] or current['fallback']) else 'invalid-json' if not current['json_valid'] else 'error' if (current['has_error'] and current['error_code']) or not 200<=current['status']<=206 else 'invalid-json' if route=='token' and not current['has_result'] else 'token' if route=='token' else 'original'
            events.clear();constructed.clear()
            for at,size in ((owner,0x200),(weak,0x20),(closure,0x60),(response,0x80),(pair,16),(sdk,0x200)):
                uc.mem_write(at,bytes(size))
            put(closure,owner);put(closure+8,context if current['lifetime']!='owner-missing' else 0)
            put(closure+0x10,weak if current['lifetime']!='weak-missing' else 0)
            put(closure+0x18,sdk);put(closure+0x30,sdk)
            initial=0 if current['lifetime']=='weak-expired' else 2
            put(weak+8,initial,4);put(weak+0xc,1,4);put(pair,response);put(pair+8,0)
            put(0x14b2f214b,int(current['lifetime']=='shutdown'),1)
            state.clear();state.update(callback=callback,result=response if category=='original' else result,
                control=0 if category=='original' else control,refs=0 if category=='original' else 1)
            uc.reg_write(x.UC_X86_REG_RDX,pair)
            try:h.call(entry,closure,budget=100000)
            except Exception as exception:raise RuntimeError('Response '+route+' '+str(config)+' stopped at '+hex(reg('RIP'))) from exception
            if get(weak+8,4)!=initial:raise ValueError('Response changed owner strong reference count')
            if category=='none':
                if events or constructed:raise ValueError('Inactive response dispatched a result')
            else:
                if events!=['copy-empty-delegate','copy-empty-delegate','allocate','queue-transfer','temporary-cleanup']:
                    raise ValueError('Response did not dispatch exactly once')
                if category=='original':
                    if constructed:raise ValueError('Sign-in success replaced original response')
                else:
                    if len(constructed)!=1 or constructed[0]['kind']!=category:
                        raise ValueError('Response constructed wrong result category')
                    stage={'transport':4 if route=='token' else 10,'invalid-json':5 if route=='token' else 11,
                        'error':6 if route=='token' else 12,'token':0}[category]
                    if constructed[0]['stage']!=stage:raise ValueError('Response result stage differs')
                    expected_category={'transport':0x1315410,'invalid-json':0x262f640,'error':0x1ca86d0,'token':0}[category]
                    if constructed[0]['category']!=expected_category:raise ValueError('Response result category differs')
                    if category=='transport' and constructed[0]['code']!=current['status']:
                        raise ValueError('Transport error lost response status')
                    if category=='error' and constructed[0]['code']!=(current['error_code'] if current['has_error'] and current['error_code'] else current['status']):
                        raise ValueError('Response SDK error/HTTP precedence differs')
                    if get(control+8,4)!=1:raise ValueError('Response did not leave exactly one queue result reference')
                    put(control+8,0,4)  # Explicit test-owned queue release; no destructor claim.
            rows.append(dict(route=route,inputs=config,category=category,constructors=constructed.copy(),
                owner_refs=initial,events=events.copy()))
    return dict(helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),cases=rows,conversion_import=identity,
        limits=['Whole callbacks, dispatchers and temporary cleanup execute. HTTP predicates/status/body, JSON parse/getters, numeric conversion, result constructors and SDK mutations are fixtures.',
            'Token string is empty and sign-in nested result has no identity fields. Actual successful identity/token/credential context remains unproven.',
            'Input HTTP response control is null; queue consumer/destructors/nonempty delegates and real network are not exercised.'])
