"""Whole launcher result dispatchers; explicit empty delegate and queue ownership boundaries."""
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
SHA='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run():
    h=load('native-request-harness-11316').make_harness(
        {'run-fcd0aa6ac1ac':'b84631a01e8c4b0cd4a961bd943315d763096114daba4582eca82e4c96426fa3',
         'run-d9172c33c6b8':'ac9cff086151c3c3025feb7b738d02dd6aabb5c47feea45a1744bc7b913a4cfe'},
        {0x1444e57f0,0x1444e6ac0,0x1444c59f0},source_sha256=SHA,copy_thunk=None)
    native=load('build-native-entry-code');shapes=load('audit-launcher-shape-11318')
    coverage={f['address']:len(shapes.normalize_function(native,h.image,f)['shape']) for f in h.fragments}
    uc,x,b=h.uc,h.x,h.scratch
    owner,pair,result,control,payload=[b+n for n in (0x1000,0x3000,0x4000,0x5000,0x6000)]
    state={};events=[]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def get(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def put(at,n,size=8):uc.mem_write(at,int(n).to_bytes(size,'little'))
    def copy_empty(machine):
        if get(reg('RDX')) or get(reg('RDX')+8,4):
            raise ValueError('Only empty saved delegates admitted in this replay')
        uc.mem_write(reg('RCX'),bytes(16));events.append('copy-empty-delegate');h.finish(reg('RCX'))
    def allocate(machine):
        if reg('RCX')!=0x30:raise ValueError('Dispatcher payload allocation differs')
        events.append('allocate');h.finish(payload)
    def queue(machine):
        at=reg('RDX')
        if reg('RCX')!=1 or get(at)!=state['callback'] or get(at+0x10)!=payload:
            raise ValueError('Dispatcher queue callback/payload differs')
        if [get(payload+n) for n in (0,8,0x10,0x20,0x28)]!=[
                0x149538388,owner,0,state['result'],state['control']] or get(payload+0x18,4):
            raise ValueError('Dispatcher queue native capture differs')
        if state['control'] and get(control+8,4)!=state['refs']+2:
            raise ValueError('Dispatcher did not retain temporary and queued result references')
        # Explicit queue ownership transfer. No worker/callback is executed here.
        put(at,0);put(at+0x10,0);events.append('queue-transfer');h.finish()
    def cleanup(machine):
        at=reg('RCX')
        if [get(at+n) for n in (0,8,0x18,0x20)]!=[owner,0,state['result'],state['control']]:
            raise ValueError('Dispatcher temporary result capture differs')
        if state['control'] and get(control+8,4)!=state['refs']+2:
            raise ValueError('Unexpected temporary cleanup count')
        # Observation only: native cleanup performs the reference decrement.
        events.append('temporary-cleanup')
    def unexpected(machine):raise ValueError('Empty dispatcher reached a nonempty callback/destruction branch')
    for at,fn in {0x141425dd0:copy_empty,0x14148fb60:allocate,0x141409d30:queue,
        0x141436cc0:unexpected,0x141483080:unexpected}.items():h.add_fixture(at,fn)
    import unicorn
    uc.hook_add(unicorn.UC_HOOK_CODE,lambda machine,at,size,user:cleanup(machine),
        begin=0x1444c59f0,end=0x1444c59f0)
    put(0x14b5652e0,0,1);put(0x14b1880f4,0,1)
    cases=[]
    for route,entry,slot,callback in (('token',0x1444e57f0,0x188,0x1444dec90),
                                      ('sign-in',0x1444e6ac0,0x98,0x1444def50)):
        for has_result in (False,True):
            for refs in (0,1,2,7):
                uc.mem_write(owner,b'\xa5'*0x200);uc.mem_write(control,bytes(0x20));uc.mem_write(payload,b'\xa5'*0x30)
                uc.mem_write(owner+slot,bytes(16));uc.mem_write(result,b'\x5a'*0x40)
                state.clear();state.update(callback=callback,result=result if has_result else 0,
                    control=control if refs else 0,refs=refs)
                put(pair,state['result']);put(pair+8,state['control']);put(control+8,refs,4)
                before_owner=bytes(uc.mem_read(owner,0x200));before_pair=bytes(uc.mem_read(pair,16))
                events.clear();uc.reg_write(x.UC_X86_REG_RDX,pair);h.call(entry,owner)
                if events!=['copy-empty-delegate','copy-empty-delegate','allocate','queue-transfer','temporary-cleanup']:
                    raise ValueError('Dispatcher capture/queue/cleanup ordering differs')
                if bytes(uc.mem_read(owner,0x200))!=before_owner or bytes(uc.mem_read(pair,16))!=before_pair:
                    raise ValueError('Dispatcher changed caller owner/input pair')
                if bytes(uc.mem_read(result,0x40))!=b'\x5a'*0x40:
                    raise ValueError('Dispatcher changed opaque result storage')
                queued_refs=get(control+8,4) if refs else None
                if refs and queued_refs!=refs+1:raise ValueError('Queued reference did not survive dispatcher return')
                # Test-owned release of the captured queue reference. The actual
                # engine consumer/destructor remains outside this scenario.
                if refs:put(control+8,queued_refs-1,4)
                cases.append(dict(route=route,has_result=has_result,initial_refs=refs,
                    queued_refs=queued_refs,released_refs=get(control+8,4),events=events.copy()))
    audit=load('audit-client-release')
    report=dict(source_sha256=SHA,tool_sha256=audit.sha256(Path(__file__)),exports=h.evidence,
        coverage=coverage,cases=cases,native_execution=True,network_used=False,profile_activation=False,
        compatibility='not_established',limits=[
            'Whole dispatcher roots, temporary cleanup and native reference increments/decrement execute; saved delegates are empty and diagnostics disabled.',
            'Delegate copy, allocator and queue ownership transfer are explicit fixtures.',
            'Queue callback/consumer, nonempty delegates, destruction, response callbacks, JSON/HTTP and active SDK context are not executed.',
            'Fixture queue release is test-owned, not proof of engine callback delivery or lifetime completion.'])
    return audit.save_snapshot(h.root/'code-clues/launcher-dispatch-11318',report),report


if __name__=='__main__':
    path,result=run();print(json.dumps(dict(artifact=str(path),cases=len(result['cases']))))
