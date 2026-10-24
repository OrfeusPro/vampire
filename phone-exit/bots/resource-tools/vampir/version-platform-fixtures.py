"""FName/type/value boundaries for whole Version platform integration."""
from pathlib import Path
import struct

SCENARIOS = (
    dict(name='windows-cached',platform='Windows',present=True,cached=True,values=[1,2,3],count=3),
    dict(name='windows-cold',platform='Windows',present=True,cached=False,values=[1,2,3],count=3),
    dict(name='windows-absent',platform='Windows',present=False,cached=False,values=[],count=0),
    dict(name='windows-missing',platform='Windows',present=True,cached=True,values=[1,2],count=2),
    dict(name='windows-duplicate',platform='Windows',present=True,cached=True,values=[3,3],count=2),
    dict(name='windows-negative-count',platform='Windows',present=True,cached=True,values=[],count=-1),
    dict(name='android-cold',platform='Android',present=True,cached=False,values=[1,2,3],count=3),
    dict(name='ios-cold',platform='IOS',present=True,cached=False,values=[1,2,3],count=3),
    dict(name='unknown-cold',platform='Linux',present=True,cached=False,values=[1,2,3],count=3),
)


def install(load,h,context,shared,state,store,write_text,literal,reg):
    if context['source_sha256']!=h.sha or Path(context['source']).resolve()!=h.source.resolve():
        raise ValueError('Integrated platform source differs')
    native=load('build-native-entry-code');rows=load('update-bindings').rows
    functions={int(context[key],16):key for key in ('selector','store','lookup')}
    calls={hex(r['address']):hex(r['direct_target']) for at in functions for r in rows(native,h.image,at) if r['call']}
    if calls!=context['call_sites']:raise ValueError('Integrated platform call sites differ')
    fixture={key:int(value,16) for key,value in context['fixtures'].items()}
    if fixture['free']!=shared['free']:raise ValueError('Integrated platform free binding differs')
    cache=int(context['cache'],16);array=h.scratch+0x4000

    def handler(name):
        def execute(machine):
            a,b,c=[reg(key) for key in ('RCX','RDX','R8')];result=0
            state['platform_events'].append(name)
            if name=='platform_text':result=write_text(a,state['platform_scenario']['platform'])
            elif name=='name_ctor':
                if c!=1 or literal(b,True)!=state['platform_scenario']['platform']:
                    raise ValueError('Integrated FName constructor input differs')
                h.uc.mem_write(a,struct.pack('<Q',0x12345678))
            elif name=='equals':
                if a!=0x12345678:raise ValueError('Integrated FName token differs')
                text=literal(b,True)
                if text not in ('Android','IOS','Windows'):raise ValueError('Integrated platform literal differs')
                state['platform_compares'].append(text)
                result=128 if text==state['platform_scenario']['platform'] else 0
            elif name=='store_type':result=0x1234
            elif name=='store_resolve':
                if (a,b,c)!=(int(context['factory'],16),0x1234,int(context['descriptor'],16)):
                    raise ValueError('Integrated platform resolver inputs differ')
                result=store if state['present'] else 0
            elif name=='value_at':
                if a!=store or c!=state['platform_index']:raise ValueError('Integrated platform lookup index differs')
                state['context_calls']+=1;result=write_text(b,state['context_text'])
            else:raise ValueError('Unknown integrated platform fixture')
            h.finish(result)
        return execute
    for name,address in fixture.items():
        if name!='free':h.add_fixture(address,handler(name))
    import unicorn
    def count(machine,address,size,unused):
        if address in functions:
            key=functions[address];state['platform_calls'][key]=state['platform_calls'].get(key,0)+1
    h.uc.hook_add(unicorn.UC_HOOK_CODE,count)

    def seed(scenario):
        selector={'Android':1,'IOS':2,'Windows':3}.get(scenario['platform'],0)
        values=scenario['values'][:max(scenario['count'],0)]
        index=values.index(selector) if selector in values else 0xffffffff
        state.update(platform_scenario=scenario,platform_events=[],platform_compares=[],platform_calls={},
            platform_index=index,selector=selector,context_text=scenario['platform'] if index!=0xffffffff else '')
        h.uc.mem_write(cache,struct.pack('<Q',store if scenario['cached'] else 0))
        h.uc.mem_write(store,b'\xa5'*0x40+struct.pack('<Qi',array,scenario['count'])+b'\xa6'*20)
        h.uc.mem_write(array,(b''.join(struct.pack('<QQ',0x100+i,value) for i,value in enumerate(values))).ljust(128,b'\x5a'))
        state['platform_store_before']=bytes(h.uc.mem_read(store,96))
        state['platform_array_before']=bytes(h.uc.mem_read(array,128))

    def check():
        scenario=state['platform_scenario'];selector=state['selector']
        expected=['Android','IOS','Windows'][:selector] if selector in (1,2) else ['Android','IOS','Windows']
        if state['platform_compares']!=expected:raise ValueError('Integrated platform comparison order differs')
        events=['platform_text','name_ctor']+['equals']*len(expected)
        if not scenario['cached']:events+=['store_type','store_resolve']
        if scenario['present']:events+=['value_at']
        if state['platform_events']!=events:raise ValueError('Integrated platform lifecycle differs')
        if state['platform_calls']!=dict(selector=1,store=1,**({'lookup':1} if scenario['present'] else {})):
            raise ValueError('Integrated platform entries differ')
        if (bytes(h.uc.mem_read(store,96))!=state['platform_store_before']
                or bytes(h.uc.mem_read(array,128))!=state['platform_array_before']
                or int.from_bytes(h.uc.mem_read(cache,8),'little')!=(store if scenario['present'] else 0)):
            raise ValueError('Integrated platform memory/cache differs')
    return seed,check
