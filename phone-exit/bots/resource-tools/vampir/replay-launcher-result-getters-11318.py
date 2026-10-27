"""Whole current result getter/type gates with explicit JSON storage/conversion fixtures."""
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
SHA='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
KEYS=(('errorCode',0x1411b0350,0x14952cde0,0x14b563da0),
      ('resultData',0x1411b05c0,0x14952ce60,0x14b563df0))


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run():
    h=load('native-request-harness-11316').make_harness(
        {'run-8b262adbaa98':'6da48cc0ed1312cb30f3141e86f01ea9569ae81b4f08d853c2efca264bd98fcb',
         'run-e62a0e8d1709':'86c20afa2e8d7546a37a657bf4222ded251531f2e7cae4375cddc1eaaa69c1c7'},
        {0x1411b0350,0x1411b05c0,0x14447d210,0x14447d460,0x14447d8f0,0x14447d4e0,0x144472080},
        source_sha256=SHA,copy_thunk=None)
    native=load('build-native-entry-code');shapes=load('audit-launcher-shape-11318')
    coverage={f['address']:len(shapes.normalize_function(native,h.image,f)['shape']) for f in h.fragments}
    uc,x,b=h.uc,h.x,h.scratch
    wrapper,root,table,pair,obj,value,output,lookup_pair,key=[b+n for n in
        (0x1000,0x2000,0x3000,0x4000,0x5000,0x6000,0x7000,0x8000,0x9000)]
    current={};events=[]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def get(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def put(at,n,size=8):uc.mem_write(at,int(n).to_bytes(size,'little'))
    def string(at,text):
        pointer=b+0xa000+(at%0x1000)*2
        if len(text)>128:raise ValueError('Getter fixture string bound')
        uc.mem_write(pointer,(text+'\0').encode('utf-16le'))
        put(at,pointer);put(at+8,len(text)+1,4);put(at+12,len(text)+1,4)
    def text(at):
        count=get(at+8,4)
        if count>129:raise ValueError('Getter FString bound')
        return bytes(uc.mem_read(get(at),count*2)).decode('utf-16le').rstrip('\0') if count else ''
    def wide(machine):
        at=reg('RDX');off=h.image.offset(at-h.image.pe.base)
        expected=next((k for k in KEYS if k[2]==at),None)
        if expected:
            if reg('RCX')!=expected[3] or h.raw[off:off+len((expected[0]+'\0').encode('utf-16le'))]!=(expected[0]+'\0').encode('utf-16le'):
                raise ValueError('Result key initializer differs')
            string(reg('RCX'),expected[0])
        else:
            label=h.raw[off:off+16].decode('utf-16le').split('\0')[0]
            if label not in ('true','false'):raise ValueError('Boolean literal differs')
            string(reg('RCX'),label)
        h.finish(reg('RCX'))
    def get_object(machine):
        if reg('RCX')!=root:raise ValueError('Result root getter receiver differs')
        put(reg('RDX'),0 if current['gate']=='missing-pair' else pair)
        events.append('get-object');h.finish(current['gate']!='getter-false')
    def find(machine):
        if reg('RCX')!=obj:raise ValueError('Field lookup receiver differs')
        view=reg('R8');count=get(view+8,4)
        expected=current['key']
        if count!=len(expected) or (bytes(uc.mem_read(get(view),count*2)).decode('utf-16le') if count else '')!=expected:
            raise ValueError('Field lookup key view differs')
        put(reg('RDX'),value if current['found'] else 0);put(reg('RDX')+8,0)
        events.append('lookup');h.finish(reg('RDX'))
    def copy_pair(machine):
        at=reg('RDX');uc.mem_write(reg('RCX'),bytes(uc.mem_read(at,16)));h.finish(reg('RCX'))
    def move_control(machine):
        if get(reg('RDX'))!=0:raise ValueError('Only null shared control fixture is supported')
        put(reg('RCX'),0);put(reg('RDX'),0);h.finish(reg('RCX'))
    def copy_string(machine):
        if reg('RCX')!=value:raise ValueError('String value receiver differs')
        string(reg('RDX'),current['string']);events.append('string');h.finish(reg('RDX'))
    def number_string(machine):
        if reg('RCX')!=value:raise ValueError('Numeric string receiver differs')
        string(reg('RDX'),current['string']);events.append('number-string');h.finish(current['numeric_string'])
    def format_number(machine):
        if reg('XMM1')!=0x42f60000 or reg('R8')!=0:raise ValueError('Numeric fallback arguments differ')
        string(reg('RCX'),'fixture-number');events.append('format-number');h.finish(reg('RCX'))
    def number_value(machine):
        if reg('RCX')!=value:raise ValueError('Numeric value receiver differs')
        uc.reg_write(x.UC_X86_REG_XMM0,0x42f60000);h.finish()
    fixtures={0x141426b30:wide,0x1487e976c:lambda machine:h.finish(),
        b+0x12000:get_object,b+0x12100:number_string,
        0x1415f3640:find,0x144475160:copy_pair,0x1415ea310:copy_string,
        0x1415ea1a0:number_value,0x141438260:format_number,
        0x1415ea150:lambda machine:h.finish(current['boolean']),
        0x1414734e0:move_control,0x141483080:lambda machine:(events.append('free-partial'),h.finish())}
    for at,fn in fixtures.items():h.add_fixture(at,fn)
    put(table+0x80,b+0x12000);put(table+0x58,b+0x12100)
    for label,entry,_,global_at in KEYS:
        h.call(entry)
        if text(global_at)!=label:raise ValueError('Initialized result key differs')
    cases=[]
    for kind,entry in (('string',0x14447d460),('object',0x14447d210)):
     for gate in ('null-root','wrong-root-type','getter-false','missing-pair','null-object','ready'):
      for field_type in (0,2,3,4,6):
       for variant in (False,True):
        current.clear();current.update(gate=gate,found=variant,boolean=variant,numeric_string=variant,
            string='fixture-строка' if variant else '',key='resultData')
        events.clear();uc.mem_write(b+0x35000,bytes(0x3000))
        for at in (wrapper,root,pair,obj,value,output,lookup_pair,key):uc.mem_write(at,bytes(0x100))
        put(wrapper,0 if gate=='null-root' else root);put(root,table)
        put(root+8,5 if gate=='wrong-root-type' else 6,4);put(pair,0 if gate=='null-object' else obj)
        put(value,table);put(value+8,field_type,4)
        uc.mem_write(output,b'\xcc'*0x38)
        uc.reg_write(x.UC_X86_REG_RDX,output);uc.reg_write(x.UC_X86_REG_R8,0x14b563df0)
        result=h.call(entry,wrapper)
        valid=gate=='ready' and variant
        if result!=output:raise ValueError('Getter return pointer differs')
        if kind=='object':
            if get(output)!=(value if valid and field_type==6 else 0):raise ValueError('Object type gate differs')
            if bytes(uc.mem_read(output+8,0x18))!=bytes(0x18) or bytes(uc.mem_read(output+0x28,0x10))!=bytes(0x10):
                raise ValueError('Object wrapper defined fields not cleared')
            if bytes(uc.mem_read(output+0x20,8))!=b'\xcc'*8:
                raise ValueError('Object wrapper untouched region differs')
        else:
            expected=current['string'] if valid and field_type in (2,3) else 'true' if valid and field_type==4 else ''
            if text(output)!=expected:raise ValueError('String projection differs')
        if events.count('lookup')!=int(gate=='ready'):raise ValueError('Root lookup gate differs')
        cases.append(dict(kind=kind,gate=gate,field_type=field_type,found=variant,events=events.copy()))
    # Direct string conversion exercises both boolean values and numeric fallback,
    # independent of the missing-field branch of the lookup fixture.
    conversions=[]
    for numeric_string,boolean in ((False,False),(False,True),(True,False),(True,True)):
     for field_type in (2,3,4):
        current.update(numeric_string=numeric_string,boolean=boolean,string='fixture-direct')
        events.clear();put(wrapper,value);put(wrapper+8,0);put(value+8,field_type,4)
        uc.reg_write(x.UC_X86_REG_RDX,output);h.call(0x14447d4e0,wrapper)
        expected='fixture-direct' if field_type==2 or (field_type==3 and numeric_string) else (
            'fixture-number' if field_type==3 else 'true' if boolean else 'false')
        if text(output)!=expected:raise ValueError('Direct conversion fallback differs')
        conversions.append(dict(field_type=field_type,numeric_string=numeric_string,boolean=boolean,events=events.copy()))
    audit=load('audit-client-release')
    report=dict(source_sha256=SHA,tool_sha256=audit.sha256(Path(__file__)),exports=h.evidence,coverage=coverage,
        cases=cases,conversions=conversions,keys=[k[0] for k in KEYS],native_execution=True,network_used=False,
        profile_activation=False,compatibility='not_established',
        limits=['Whole lookup/getter/type conversion wrappers and two key initializers execute; JSON storage/getters, string/number conversion, allocation/free and shared-pair move are fixtures.',
            'Shared control blocks are null; last-reference destruction is not executed. Numeric conversion/formatting uses synthetic fixture values.',
            'No callback HTTP/errorCode gate, dispatcher, actual response JSON, SDK context or live auth.'])
    path=audit.save_snapshot(h.root/'code-clues/launcher-result-getters-11318',report)
    return path,report


if __name__=='__main__':
    path,result=run();print(json.dumps(dict(artifact=str(path),cases=len(result['cases']),conversions=len(result['conversions']))))
