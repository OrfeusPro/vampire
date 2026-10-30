"""Exact bounded Login registration-helper outcomes; no container or dispatch claim."""
import hashlib
import itertools
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAMILY = 'login-registration'
NAME_VARIANTS = ('null_pointer', 'zero_count_fallback', 'nonnull_empty', 'short_ascii', 'unicode', 'ascii127', 'ascii128')
NAME_TEXT = dict(null_pointer=None,zero_count_fallback='',nonnull_empty='',short_ascii='PktLoginResult',unicode='Ж界🙂',
    ascii127='x'*127,ascii128='x'*128)


def tools():
    names=('login-registration-case-contracts.py','verify-login-registration-context.py','verify-login-registration-harness.py')
    return {str(HERE/n): hashlib.sha256((HERE/n).read_bytes()).hexdigest() for n in names}


def canonical(value): return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)

def case_count(): return 34

def verifier(): return 'verify-login-registration-context'


def name_values(variant):
    if variant not in NAME_VARIANTS: raise ValueError('Registration name variant differs')
    text=NAME_TEXT[variant]
    count=0 if variant=='zero_count_fallback' else 1
    pointer='null' if variant=='null_pointer' else 'ignored_nonnull' if variant=='zero_count_fallback' else 'name_buffer'
    return dict(text=text,count=count,pointer=pointer)


def scenarios():
    rows=[dict(insert_status=flag,poison=poison,name_variant=None,current_pair_nonnull=True)
        for flag,poison in itertools.product((1,2,255),(0x55,0xaa))]
    rows += [dict(insert_status=0,poison=poison,name_variant=variant,current_pair_nonnull=nonnull)
        for variant,nonnull,poison in itertools.product(NAME_VARIANTS,(False,True),(0x55,0xaa))]
    return rows


def event(action,offset,**fields): return dict(action=action,call_offset=offset,arguments_checked=True,**fields)


def expected_case(scenario):
    scenario=dict(scenario);flag=scenario['insert_status'];nonnull=scenario['current_pair_nonnull']
    pointer='current_pair_fixture' if nonnull else 'null'
    events=[event('native_id',59,packet_id=4),event('insert',91,owner_offset=8,key=4,
        original_packet='input_packet',original_handler='input_handler',input_captured_before_output=True,
        output_pointer=pointer,output_status=flag)]
    allocated=False
    if flag==0:
        name=name_values(scenario['name_variant']);text=name['text']
        events.append(event('name',126,descriptor_count=name['count'],descriptor_pointer=name['pointer'],
            returned_descriptor='external_fixture',name_outparam_unchanged=True))
        if text is not None:
            units=len(text.encode('utf-16le'))//2;data=text.encode('utf-8');allocated=len(data)+1>128
            events.append(event('utf8_length',193,utf16_units=units,utf8_bytes=len(data)))
            if allocated: events.append(event('diagnostic_allocate',241,bytes=len(data)+1,stride=1))
            events.append(event('utf8_convert',275,utf16_units_with_nul=units+1,capacity=len(data)+1,
                destination='heap' if allocated else 'stack',utf8_hex=data.hex()))
        events += [event('native_id',290,packet_id=4),event('log',321,packet_id=4,line=0xb27,
            utf8_hex=None if text is None else text.encode('utf-8').hex())]
        if allocated: events.append(event('free',343,allocation='diagnostic_temporary',origin='diagnostic_allocation_fixture'))
        if nonnull: events.append(event('free',358,allocation='current_pair_fixture',origin='insert_out_pointer_preserved_by_name_fixture'))
    events.append(event('security',370,cookie_checked=True))
    return dict(scenario=scenario,events=events,native_id_calls=1 if flag else 2,diagnostic_allocated=allocated,
        diagnostic_freed=allocated,current_pair_freed=bool(not flag and nonnull),
        original_packet_freed=False,packet_unchanged=True,handler_unchanged=True,owner_unchanged=True,
        name_buffer_unchanged=True,guards=True,abi=True)


def expected_rows(): return [expected_case(s) for s in scenarios()]


def validate_report(report,context):
    if (not isinstance(report,dict) or type(report.get('schema')) is not int or report['schema']!=1
            or report.get('method')!='bounded_native'):
        raise ValueError('Login registration report schema/method differs')
    for flag in ('network_used','profile_activated','runtime_activated','native_owner_used','native_window_used',
        'native_packet_constructor_used','native_handler_used','native_insert_backend_used','native_name_getter_used',
        'native_utf8_conversion_used','native_dispatch_used','session_executed'):
        if report.get(flag) is not False: raise ValueError('Login registration boundary differs: '+flag)
    for flag in ('native_registration_helper_used','native_id_getter_used','name_outparam_unchanged','actual_ownership_unknown'):
        if report.get(flag) is not True: raise ValueError('Login registration native scope differs: '+flag)
    if context.get('format')!='login-registration-v1' or context.get('packet_bytes')!=352 or context.get('packet_allocation_bytes')!=344:
        raise ValueError('Login registration context layout differs')
    if len(scenarios())!=case_count() or canonical(report.get('cases'))!=canonical(expected_rows()):
        raise ValueError('Login registration matrix/outcome differs')
