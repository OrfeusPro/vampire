"""Expected dispatch observations; native snapshots are supplied by the runtime."""
import copy
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


COMPOSITION=load('login-composition-case-contracts')
CLEANUP=['reader','buffer','archive','base']
FLAGS=('registry_unchanged','packet_unchanged_by_handler','source_buffers_unchanged','abi','guards','fixture_writes_bounded')


def canonical(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)


def expected_setup(spec):
    lookup=spec['kind']=='lookup'
    if lookup:
        keys=spec['keys']
        if len(set(keys))!=len(keys) or len(keys)>8:raise ValueError('Dispatch lookup keys differ')
        inserts=len(keys);constructors=0;registers=0
    else:
        keys=spec.get('before_keys',[])+[4]+spec.get('after_keys',[])
        if len(set(keys))!=len(keys) or len(keys)>9:raise ValueError('Dispatch delivery keys differ')
        inserts=len(keys);constructors=1;registers=1
    if any(type(key) is not int or not 0<=key<=0xffff for key in keys):raise ValueError('Dispatch key range differs')
    return dict(packet_constructor_calls=constructors,register_calls=registers,insert_calls=inserts,
        rehash_calls=int(inserts>8),string_constructor_calls=constructors,
        bindings_checked=True,initial_active_null=True,initial_tls_null=True)


def _ordinary(spec,include_setup=True):
    kind=spec['kind'];reader=None;handler=None
    is_lookup=kind=='lookup';unknown=kind=='unknown'
    if kind not in ('lookup','unknown','delivery'):raise ValueError('Dispatch ordinary kind differs')
    packet_id=spec['query'] if is_lookup else spec['packet_id'] if unknown else 4
    if type(packet_id) is not int or not 0<=packet_id<=0xffff:raise ValueError('Dispatch packet ID differs')
    found=packet_id in spec['keys'] if is_lookup else not unknown
    successful=False;failed=False;archive=None;diagnostics=[]
    if kind=='delivery':
        child=COMPOSITION.expected_case(spec['composition']);reader=child['reader'];handler=child['handler']
        successful=child['handler_invoked'];failed=not successful
        archive=dict(flags=1,fifth_arg=0,source_offset=5,size=reader['size'],consumed=reader['consumed'],
            cleanup_chain=list(CLEANUP),final_buffer='null',final_length=0,final_cursor='null',final_swap=0,final_vptr_checked=True)
    if not found:diagnostics=[dict(line=0xadc if is_lookup else 0xaf8,packet_id=packet_id,name_hex=None)]
    elif failed:diagnostics=[dict(line=0xb0b,packet_id=4,name_hex=b'PktLoginResult'.hex())]
    gate=int(successful and spec['composition']['scenario'].get('code',0) not in (54,9818,9819,90021)) if kind=='delivery' else 0
    dispatch=dict(packet_id=packet_id,found=found,dispatch_calls=0 if is_lookup else 1,lookup_calls=int(is_lookup),
        reader_calls=int(kind=='delivery'),handler_calls=int(successful),wrapper_calls=int(successful),gate_calls=gate,
        tls_set_calls=['owner','null'] if kind=='delivery' else [],tls_at_reader='owner' if kind=='delivery' else None,
        tls_at_handler='owner' if successful else None,tls_after='null',active_at_handler='packet' if successful else None,
        active_after='null',active_writes=['packet','null'] if successful else [],archive=archive,diagnostics=diagnostics,
        name_getter_calls=int(failed),name_constructor_calls=int(failed),name_buffer_freed=failed,
        lookup_returned_handler='handler_'+str(spec['keys'].index(packet_id)) if is_lookup and found else None)
    result=dict(spec=copy.deepcopy(spec),reader=copy.deepcopy(reader),handler=copy.deepcopy(handler),dispatch=dispatch,
        **dict.fromkeys(FLAGS,True),packet_reseeded=False)
    if include_setup:result['setup']=expected_setup(spec)
    return result


def expected_case(spec):
    if spec['kind']!='reuse':return _ordinary(spec)
    contract=load('login-dispatch-case-contracts')
    return dict(spec=copy.deepcopy(spec),setup=expected_setup(spec),steps=[_ordinary(child,False) for child in contract.reuse_steps(spec)],
        shared_owner=True,shared_packet=True,registry_rebuilt=False,packet_reconstructed=False,
        packet_after_failures_unchanged=True,abi=True,guards=True)


def expected_step(spec):return _ordinary(spec,False)


def validate_case(row,spec):
    if not isinstance(row,dict):raise ValueError('Dispatch actual row differs')
    wanted=expected_case(spec)
    if canonical(row)!=canonical(wanted):
        if set(row)!=set(wanted):raise ValueError('Dispatch case fields differ')
        for key in wanted:
            if canonical(row[key])!=canonical(wanted[key]):raise ValueError('Dispatch case '+key+' differs')
        raise ValueError('Dispatch case differs')
    return row
