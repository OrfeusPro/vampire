"""Bounded native registry-to-Login delivery, lookup and paired reuse matrix."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
FAMILY='login-dispatch'
SCOPE='bounded_native_login_dispatch_delivery'


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


COMPOSITION=load('login-composition-case-contracts')
TRUE_FLAGS=('native_packet_constructor_used','native_reader_used','native_handler_used','native_gate_used',
    'native_registration_helper_used','native_insert_backend_used','native_rehash_used','native_name_getter_used',
    'native_string_constructor_used','native_dispatch_used','native_lookup_used','native_tls_setter_used',
    'native_archive_cleanup_used','native_handler_wrapper_used','native_input_utf8_used')
FALSE_FLAGS=('network_used','profile_activated','runtime_activated','native_owner_used','native_window_used',
    'native_os_tls_provider_used','native_allocators_used','native_sized_free_used','native_bucket_vector_reset_used',
    'native_diagnostic_utf8_used','native_post_state_used','native_continuation_used','session_executed')


def canonical(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)


def tools():
    return {**COMPOSITION.tools(),**{str(HERE/n):hashlib.sha256((HERE/n).read_bytes()).hexdigest() for n in
        ('login-dispatch-case-contracts.py','login-dispatch-oracle.py','login-dispatch-handler-fixtures.py',
         'verify-login-dispatch-context.py','verify-login-dispatch-harness.py')}}


def case_count():return 107
def verifier():return 'verify-login-dispatch-context'


def delivery(label,composition,*,group='composition',before=(),after=(),tls_index=0,poison=0x55):
    return dict(kind='delivery',group=group,label=label,composition=copy.deepcopy(composition),
        before_keys=list(before),after_keys=list(after),tls_index=tls_index,poison=poison)


def lookup_seeds():
    return [('empty',[],4),('missing_zero',[4],0),('missing_ffff',[4,0x100,0x101],0xffff),('single_four',[4],4),
        ('collision_first',[4,12,20],4),('collision_middle',[12,4,20],4),('collision_last',[12,20,4],4),
        ('high_byte',[0x100,0x104,0xffff],0x104)]


def scenarios():
    rows=[delivery('composition-'+str(i),spec,tls_index=i%2,poison=spec['scenario'].get('poison',0x55))
        for i,spec in enumerate(COMPOSITION.scenarios())]
    for i,(name,keys,query) in enumerate(lookup_seeds()):
        for poison in (0x55,0xaa):
            rows.append(dict(kind='lookup',group='lookup',label=name,keys=list(keys),query=query,tls_index=i%2,poison=poison))
    for packet_id in (0,17,0x104,0xffff):
        for index in (0,1):
            rows.append(dict(kind='unknown',group='unknown',label='unknown-'+str(packet_id),packet_id=packet_id,
                tls_index=index,poison=0x55 if index==0 else 0xaa))
    base=dict(kind='full',scenario={})
    focused=[('collision_before',[12,20,68],[]),('collision_after',[],[12,20,68]),
        ('high_byte',[0x100,0x104,0xffff],[]),('growth',[0,1,2,3,5,6,7,8],[])]
    for i,(name,before,after) in enumerate(focused):
        rows.append(delivery(name,base,group='focused',before=before,after=after,tls_index=i%2,poison=0x55 if i%2==0 else 0xaa))
    for index in (0,1):
        rows.append(dict(kind='reuse',group='reuse',label='paired-'+str(index),tls_index=index,poison=0x55 if index==0 else 0xaa))
    return rows


def reuse_steps(spec):
    if spec['kind']!='reuse':raise ValueError('Dispatch paired reuse spec differs')
    common=dict(group='reuse-step',tls_index=spec['tls_index'],poison=spec['poison'])
    return [delivery('success',dict(kind='full',scenario={}),**common),
        delivery('empty_body',dict(kind='truncated',scenario={},fail_at=0,cut=0),**common),
        dict(kind='unknown',label='unknown_after_failure',packet_id=0xffff,**common)]


def frame_body(spec):
    if spec['kind']=='unknown':return b''
    if spec['kind']!='delivery':raise ValueError('Dispatch frame spec differs')
    child=spec['composition'];body,_,_=COMPOSITION.encode(child['scenario'])
    if child['kind']=='truncated':return body[:child['cut']]
    if child['kind']=='trailing':return body+bytes.fromhex(child['tail_hex'])
    if child['kind']!='full':raise ValueError('Dispatch composition kind differs')
    return body


def expected_case(spec):return load('login-dispatch-oracle').expected_case(spec)
def expected_setup(spec):return load('login-dispatch-oracle').expected_setup(spec)


def validate_report(report,context):
    if (not isinstance(report,dict) or type(report.get('schema')) is not int or report['schema']!=1
            or report.get('method')!='bounded_native' or report.get('source_sha256')!=context.get('source_sha256')
            or not isinstance(context.get('source_sha256'),str) or not re.fullmatch('[0-9a-f]{64}',context['source_sha256'])
            or context.get('family')!=FAMILY or context.get('format')!='login-dispatch-v1'):
        raise ValueError('Dispatch source/schema/method differs')
    if 'scope' in report and report['scope']!=SCOPE:raise ValueError('Dispatch report scope differs')
    for key,value in (('packet_bytes',352),('packet_allocation_bytes',344),('owner_bytes',80),('node_bytes',40),('framing_minimum',5)):
        if type(context.get(key)) is not int or context[key]!=value:raise ValueError('Dispatch '+key+' differs')
    for flag in TRUE_FLAGS:
        if report.get(flag) is not True:raise ValueError('Dispatch native scope differs: '+flag)
    for flag in FALSE_FLAGS:
        if report.get(flag) is not False:raise ValueError('Dispatch boundary differs: '+flag)
    if report.get('framing_precondition')!='frame_size_at_least_5' or report.get('initial_context_precondition')!='active_packet_and_tls_zero':
        raise ValueError('Dispatch framing/context precondition differs')
    wanted=scenarios();rows=report.get('cases')
    if len(wanted)!=case_count() or len({canonical(s) for s in wanted})!=case_count() or not isinstance(rows,list) or len(rows)!=case_count():
        raise ValueError('Dispatch exact matrix differs')
    checker=load('login-dispatch-oracle')
    for row,spec in zip(rows,wanted):checker.validate_case(row,spec)
