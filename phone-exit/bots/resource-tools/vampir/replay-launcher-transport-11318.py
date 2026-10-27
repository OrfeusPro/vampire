"""Execute complete launcher wrappers up to an explicit common-transport fixture."""
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
        {'run-236277aa9d0b':'83c2cc9ec957ea9ca3d1dfefbc73b09e2252417aeb73d45199381789c640ce53'},
        {0x144522f90,0x144523110},source_sha256=SHA,copy_thunk=None)
    index=load('knowledge-index')
    if h.sha!=SHA or any(not f.get('block_coverage_complete') or not f.get('direct_flow_coverage_complete')
        or index.missing_conditional_fallthroughs(f['instructions']) for f in h.fragments):
        raise ValueError('Launcher transport source/coverage differs')
    uc,x,b=h.uc,h.x,h.scratch
    manager,output,route,body,headers,delegate,obj,table,copied=[b+n for n in
        (0x1000,0x2000,0x3000,0x4000,0x5000,0x6000,0x7000,0x8000,0x9000)]
    current={};calls=[]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def put(at,value,size=8):uc.mem_write(at,int(value).to_bytes(size,'little'))
    def get(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def copy_callback(machine):
        expected=obj if current['mode']=='heap' else delegate+0x20
        # Source callback has already moved into a temporary object at this point.
        if current['mode']=='heap' and reg('RCX')!=expected:raise ValueError('Callback heap copy receiver')
        if current['mode']=='inline' and get(reg('RCX'))!=table:raise ValueError('Callback inline copy receiver')
        current['copy_receiver']=reg('RCX')
        put(reg('RDX'),copied);calls.append('copy');h.finish()
    def destroy_callback(machine):
        if reg('RCX')!=current.get('copy_receiver'):
            raise ValueError('Moved callback destruction receiver differs')
        calls.append('destroy');h.finish()
    def map_cleanup(machine):
        if reg('RDX')!=0:raise ValueError('Local request cleanup mode')
        calls.append('map-cleanup');h.finish()
    def unexpected_free(machine):raise ValueError('Unexpected allocation in bounded empty-map wrapper')
    def send_sink(machine):
        if reg('RCX')!=b+0xa000 or reg('RDX')!=output or reg('R8')!=route:
            raise ValueError('Common transport forwarding differs')
        stack=reg('RSP');sent_body=get(stack+0x28);closure=get(stack+0x30)
        if sent_body!=body:raise ValueError('Common transport body pointer differs')
        if current['wrapper']=='signin':
            if reg('R9')!=headers:raise ValueError('Sign-in headers forwarding differs')
        else:
            local=reg('R9')
            if get(local)!=0 or get(local+8)!=0:raise ValueError('Token local container not empty')
        if get(delegate+0x10)!=0 or get(delegate)!=0:
            raise ValueError('Input delegate not moved before send')
        active=current['mode']!='empty'
        if get(closure)!=(0x12345678 if active else 0):raise ValueError('Forwarded callback identity differs')
        if current['wrapper']=='token' and active and get(closure+0x10)!=copied:
            raise ValueError('Copied callback capture differs')
        if current['wrapper']=='signin' and active:
            if get(closure+0x10)!=(obj if current['mode']=='heap' else 0):
                raise ValueError('Sign-in capture storage differs')
            if current['mode']=='inline' and get(closure+0x20)!=table:
                raise ValueError('Sign-in inline capture differs')
        current['forwarded_headers']=reg('R9')==headers
        # The common transport boundary consumes its callback. No callback is invoked.
        put(closure,0);put(closure+0x10,0);put(output,0xabcdef)
        calls.append('send-boundary');h.finish(output)
    for at,fn in {b+0xb000:copy_callback,b+0xb100:destroy_callback,
        0x1445231a0:send_sink,0x141465560:map_cleanup,0x141483080:unexpected_free,
        0x1487e9300:lambda machine:h.finish(reg('RAX'))}.items():h.add_fixture(at,fn)
    put(table,b+0xb000);put(table+0x10,b+0xb100)
    cases=[]
    for wrapper,entry in (('token',0x144522f90),('signin',0x144523110)):
     for mode in ('empty','inline','heap'):
        current.clear();current.update(wrapper=wrapper,mode=mode);calls.clear()
        for at in (manager,output,route,body,headers,delegate,obj,copied):uc.mem_write(at,bytes(0x100))
        put(manager,b+0xa000);put(obj,table);put(copied,table)
        if mode!='empty':
            put(delegate,0x12345678);put(delegate+0x10,obj if mode=='heap' else 0);put(delegate+0x20,table)
        original={at:bytes(uc.mem_read(at,0x100)) for at in (manager,route,body,headers,obj)}
        stack=b+0x38000
        uc.reg_write(x.UC_X86_REG_RDX,output);uc.reg_write(x.UC_X86_REG_R8,route)
        if wrapper=='token':
            uc.reg_write(x.UC_X86_REG_R9,body);put(stack+0x28,delegate)
        else:
            uc.reg_write(x.UC_X86_REG_R9,headers);put(stack+0x28,body);put(stack+0x30,delegate)
        result=h.call(entry,manager)
        if wrapper=='signin' and result!=output:raise ValueError('Sign-in return pointer differs')
        if calls.count('send-boundary')!=1 or get(output)!=0xabcdef:raise ValueError('Transport boundary count/output differs')
        if calls.count('copy')!=int(wrapper=='token' and mode!='empty'):
            raise ValueError('Callback copy count differs')
        if calls.count('destroy')!=int(wrapper=='token' and mode!='empty'):
            raise ValueError('Moved callback cleanup count differs')
        if any(bytes(uc.mem_read(at,len(value)))!=value for at,value in original.items()):
            raise ValueError('Wrapper mutated borrowed inputs')
        cases.append(dict(wrapper=wrapper,mode=mode,calls=calls.copy(),headers_forwarded=current['forwarded_headers'],
            input_delegate_moved=get(delegate)==0 and get(delegate+0x10)==0))
    audit=load('audit-client-release')
    report=dict(source_sha256=SHA,tool_sha256=audit.sha256(Path(__file__)),exports=h.evidence,
        cases=cases,native_execution=True,network_used=False,profile_activation=False,compatibility='not_established',
        limits=['Whole token/sign-in wrappers execute; common transport, callback copy/destruction, empty-map cleanup and cookie are fixtures.',
            'Synthetic callback capture and empty containers only. Sink consumes callbacks but never invokes them; no request serialization/HTTP/SDK/live auth proof.'])
    path=audit.save_snapshot(h.root/'code-clues/launcher-transport-11318',report)
    return path,report


if __name__=='__main__':
    path,result=run();print(json.dumps(dict(artifact=str(path),cases=len(result['cases']))))
