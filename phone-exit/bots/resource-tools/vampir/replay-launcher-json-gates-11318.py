"""Execute whole JSON conversion gates and sparse traversal; engine writers are fixtures."""
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
        {'run-b50b7708aaa7':'2d7b244c72800a953231ce22ce063d9a856fb2326b26522eb6d1503ccc109883',
         'run-e1fd1a429120':'c24f40fa1609e8d1a99c977f38ab10b04844d87ddebd1892d6ef877e5235c44a'},
        {0x144474430,0x144489150,0x144492b40,0x14142e6f0},source_sha256=SHA,copy_thunk=None)
    native=load('build-native-entry-code');shapes=load('audit-launcher-shape-11318')
    coverage={f['address']:len(shapes.normalize_function(native,h.image,f)['shape']) for f in h.fragments}
    uc,x,b=h.uc,h.x,h.scratch
    wrapper,value,table,pair,obj,writer,holder,output,source,entries,bits=[b+n for n in
        (0x1000,0x2000,0x3000,0x4000,0x5000,0x6000,0x7000,0x8000,0x9000,0x16000,0x1e000)]
    payload=b+0x10000;current={};events=[]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def get(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def put(at,value,size=8):uc.mem_write(at,int(value).to_bytes(size,'little'))
    def fstring(at,pointer,text):
        uc.mem_write(pointer,(text+'\0').encode('utf-16le'))
        put(at,pointer);put(at+8,len(text)+1,4);put(at+12,len(text)+1,4)
    def getter(machine):
        if reg('RCX')!=value:raise ValueError('Object getter receiver differs')
        put(reg('RDX'),0 if current.get('gate')=='missing-pair' else pair)
        events.append('get-object');h.finish(current.get('gate')!='getter-false')
    def create_value(machine):
        out=reg('RCX');uc.mem_write(out,bytes(0x38));put(out,value);h.finish(out)
    def setter(machine):
        at=reg('RDX');delta=at-entries
        if reg('RCX')!=obj or delta<0 or delta%0x28 or delta//0x28 not in current['slots']:
            raise ValueError('Object map setter/key differs')
        if reg('R8')!=at+0x10:raise ValueError('Object map value pointer differs')
        events.append(delta//0x28);h.finish()
    def writer_factory(machine):
        current['string_out']=reg('RDX')
        if reg('R8')!=0:raise ValueError('Writer factory argument differs')
        put(reg('RCX'),writer);put(reg('RCX')+8,0);events.append('writer-factory');h.finish(reg('RCX'))
    def wrap_object(machine):
        if get(reg('RCX'))!=obj or get(reg('RCX')+8)!=0:
            raise ValueError('Writer object pair differs')
        put(holder+0x10,obj);events.append('wrap-object');h.finish(holder)
    def write(machine,mode):
        if get(reg('RCX'))!=holder+0x10 or reg('RDX')!=writer or reg('R8')!=1:
            raise ValueError('Writer handoff differs')
        fstring(current['string_out'],payload,'{"fixture":true}')
        events.append('writer-'+str(mode));h.finish(current['gate']!='writer-false')
    def trim(machine):
        if reg('RCX')!=current['string_out']:raise ValueError('String postprocessing receiver differs')
        events.append('postprocess');h.finish()
    def ascii_literal(machine):
        expected={0x148a14ddc:'{',0x14950c940:'}'}
        at=reg('RDX')
        if at not in expected:raise ValueError('JSON delimiter literal differs')
        off=h.image.offset(at-h.image.pe.base)
        if h.raw[off:off+2]!=(expected[at]+'\0').encode('ascii'):
            raise ValueError('JSON delimiter bytes differ')
        fstring(reg('RCX'),b+0x11000+(0 if expected[at]=='{' else 0x100),expected[at]);h.finish(reg('RCX'))
    def delimiter(machine,opening):
        if reg('RCX')!=current['string_out'] or reg('R8')!=1 or reg('R9')!=1:
            raise ValueError('Delimiter predicate arguments differ')
        expected='{' if opening else '}'
        if bytes(uc.mem_read(reg('RDX'),4))!=(expected+'\0').encode('utf-16le'):
            raise ValueError('Delimiter predicate text differs')
        events.append('opening' if opening else 'closing')
        h.finish(current['gate']!=('opening-false' if opening else 'closing-false'))
    def free(machine):
        if reg('RCX')==payload:events.append('free-output')
        h.finish()
    fixtures={0x144474fc0:create_value,0x1415f2570:setter,
        0x1415ea440:writer_factory,0x1415e4880:wrap_object,
        0x1415e5ea0:lambda machine:write(machine,0),0x1415e4e20:lambda machine:write(machine,1),
        0x14143a030:trim,0x141439db0:trim,0x141426950:ascii_literal,
        0x141438a20:lambda machine:delimiter(machine,True),
        0x14142d770:lambda machine:delimiter(machine,False),0x141483080:free,
        b+0x12000:getter}
    for at,fn in fixtures.items():h.add_fixture(at,fn)
    put(table+0x80,b+0x12000)
    def reset(gate):
        current.clear();current['gate']=gate;events.clear()
        uc.mem_write(b+0x35000,bytes(0x3000))
        for at in (wrapper,value,pair,obj,writer,holder,output,source):uc.mem_write(at,bytes(0x100))
        put(wrapper,value);put(value,table);put(value+8,6,4);put(pair,obj)
        put(holder+8,3,4);put(holder+12,3,4)
    traversals=[]
    for slots,external in (([],False),([0,1,2],False),([0,2,31],False),
                            ([31,32,65],False),([0,127,128,129],True)):
        reset('success');current['slots']=slots
        count=max(slots)+1 if slots else 0
        uc.mem_write(entries,bytes(0x2000));uc.mem_write(bits,bytes(0x100))
        put(source,entries);put(source+0x28,count,4)
        bitbase=bits if external else source+0x10
        if external:put(source+0x20,bits)
        for slot in slots:
            at=bitbase+4*(slot//32);put(at,get(at,4)|(1<<(slot%32)),4)
        uc.reg_write(x.UC_X86_REG_RDX,source)
        result=h.call(0x144474430,wrapper)
        captured=[v for v in events if isinstance(v,int)]
        if result!=wrapper or captured!=slots:raise ValueError('Native sparse traversal differs')
        traversals.append(dict(slots=slots,external_bits=external,captured=captured))
    cases=[]
    for mode in (0,1):
     for gate in ('null-value','wrong-type','getter-false','missing-pair','null-object',
                  'writer-false','opening-false','closing-false','success'):
        reset(gate);put(output,0xdeadbeef);put(output+8,0xdeadbeef)
        if gate=='null-value':put(wrapper,0)
        if gate=='wrong-type':put(value+8,5,4)
        if gate=='null-object':put(pair,0)
        uc.reg_write(x.UC_X86_REG_RDX,output);uc.reg_write(x.UC_X86_REG_R8,mode)
        returned=h.call(0x144489150,wrapper)
        success=gate=='success'
        if returned!=output or get(output)!=(payload if success else 0):
            raise ValueError('JSON conversion result pointer differs')
        if not success and get(output+8)!=0:raise ValueError('Failed JSON output not cleared')
        started=gate in ('writer-false','opening-false','closing-false','success')
        if ('writer-'+str(mode) in events)!=started:raise ValueError('Writer selection differs')
        if events.count('free-output')!=int(started and not success):raise ValueError('Partial output cleanup differs')
        if get(holder+8,4)!=(2 if started else 3):raise ValueError('Writer temporary refcount differs')
        if events.count('opening')!=int(started and gate!='writer-false'):
            raise ValueError('Opening delimiter gate order differs')
        if events.count('closing')!=int(gate in ('closing-false','success')):
            raise ValueError('Closing delimiter gate order differs')
        cases.append(dict(mode=mode,gate=gate,success=success,events=events.copy()))
    audit=load('audit-client-release')
    report=dict(source_sha256=SHA,tool_sha256=audit.sha256(Path(__file__)),exports=h.evidence,
        coverage=coverage,traversals=traversals,cases=cases,fixture_targets=[hex(a) for a in sorted(fixtures)],
        native_execution=True,network_used=False,profile_activation=False,compatibility='not_established',
        limits=['Whole object conversion, sparse iterator, string wrapper and serializer gate functions execute.',
            'Object constructor/getter/setter, writers, string predicates/postprocessing, allocation/free boundaries are fixtures.',
            'Writer fixture produces a fixed synthetic JSON string; actual field values, escaping, writer formatting and live auth remain unknown.',
            'Source shared-object control block is null; writer refcount starts at three, so destruction branches are not executed.'])
    target=audit.save_snapshot(h.root/'code-clues/launcher-json-gates-11318',report)
    return target,report


if __name__=='__main__':
    path,result=run();print(json.dumps(dict(artifact=str(path),cases=len(result['cases']),maps=len(result['traversals']))))
