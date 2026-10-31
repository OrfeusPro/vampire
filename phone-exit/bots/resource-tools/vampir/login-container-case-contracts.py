"""Exact bounded matrix for native container insertion, rehash and name ownership."""
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
FAMILY = 'login-container'
SCOPE = 'bounded_native_login_container_and_name'
TRUE_FLAGS = ('native_registration_helper_used','native_id_getter_used','native_insert_backend_used','native_rehash_used',
    'native_name_getter_used','native_string_constructor_used')
FALSE_FLAGS = ('network_used','profile_activated','runtime_activated','native_owner_used','native_window_used',
    'native_packet_constructor_used','native_handler_used','native_bucket_vector_reset_used','native_allocators_used',
    'native_sized_free_used','native_utf8_conversion_used','native_dispatch_used','session_executed')


def oracle():
    spec = importlib.util.spec_from_file_location('login_container_oracle', HERE/'login-container-oracle.py')
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


def canonical(value): return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def tools():
    return {str(HERE/name): hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
        ('login-container-case-contracts.py','login-container-oracle.py','verify-login-container-context.py','verify-login-container-harness.py')}


def case_count(): return 120


def verifier(): return 'verify-login-container-context'


def ctor_scenarios():
    rows = []
    for name, data in (('null',None),('empty',b'')):
        for poison in (0x55,0xaa): rows.append(dict(kind='ctor', case=name, source_hex=None if data is None else data.hex(), capacity=None, poison=poison))
    nonempty = [('len'+str(n), b'x'*n) for n in (1,2,3,14,15,16,17,30,31,32,33)]
    nonempty += [('signed80',b'\x80'),('signedff',b'\xff'),('signed4',b'\x80\xffA'),
        ('signed33',b'\x80\xff'*16+b'\x80'),('embedded_nul',b'A\0ignored')]
    for (name,data), mode, poison in itertools.product(nonempty, ('exact','rounded'), (0x55,0xaa)):
        rows.append(dict(kind='ctor', case=name, source_hex=data.hex(), capacity=mode, poison=poison))
    return rows


def _map(kind, name, keys, poison, **changes):
    value = dict(kind=kind, case=name, keys=list(keys), bucket_count=8, vector_capacity=16,
        load_factor_bits='3f800000', poison=poison)
    if kind != 'rehash': value['key'] = 4
    if kind == 'fusion': value['capacity'] = 'exact'
    return dict(value, **changes)


def insert_seeds():
    return [('empty',[],{}),('other_bucket',[0,1,2],{}),('collision_one',[12],{}),('collision_chain',[12,20,68],{}),
        ('duplicate_only',[4],{}),('duplicate_first',[4,12,20],{}),('duplicate_middle',[12,4,20],{}),
        ('duplicate_last',[12,20,4],{}),('exact_load',[0,1,2,3,5,6,7],{}),
        ('growth',[0,1,2,3,5,6,7,8],{}),('collision_growth',[12,20,68,0,1,2,3,5],{}),
        ('higher_load',[0,1,2,3,5,6,0x104,0xffff],dict(load_factor_bits='40000000'))]


def scenarios():
    rows = ctor_scenarios()
    rows += [dict(kind='getter', case='fixed_packet_name', capacity=mode, poison=poison)
        for mode,poison in itertools.product(('exact','rounded'),(0x55,0xaa))]
    for name, keys, changes in insert_seeds():
        for poison in (0x55,0xaa): rows.append(_map('insert',name,keys,poison,**changes))
    rehash = [('minimum',[],1,{}),('empty_growth',[],16,dict(vector_capacity=32)),
        ('same',[0,1,4],8,{}),('split',[0x100,0x101,4],16,{}),('rounded_shrink',[4,12,20],3,{}),
        ('split_collision',[4,12,20,68],64,{})]
    for name,keys,requested,changes in rehash:
        for poison in (0x55,0xaa): rows.append(_map('rehash',name,keys,poison,requested=requested,**changes))
    fused = {'empty','collision_chain','duplicate_only','duplicate_middle','growth','collision_growth'}
    for name,keys,changes in insert_seeds():
        if name not in fused: continue
        for poison in (0x55,0xaa): rows.append(_map('fusion',name,keys,poison,**changes))
    return rows


def expected_case(scenario): return oracle().expected_case(scenario)


def validate_report(report, context):
    if (not isinstance(report,dict) or type(report.get('schema')) is not int or report['schema'] != 1
            or report.get('method') != 'bounded_native' or report.get('source_sha256') != context.get('source_sha256')
            or not isinstance(context.get('source_sha256'),str) or not re.fullmatch('[0-9a-f]{64}',context['source_sha256'])
            or context.get('family') != FAMILY or context.get('format') != 'login-container-v1'):
        raise ValueError('Container source/schema/method differs')
    if 'scope' in report and report['scope'] != SCOPE: raise ValueError('Container report scope differs')
    for key,value in (('packet_bytes',352),('packet_allocation_bytes',344),('owner_bytes',72),('node_bytes',40)):
        if type(context.get(key)) is not int or context[key] != value: raise ValueError('Container '+key+' differs')
    for flag in TRUE_FLAGS:
        if report.get(flag) is not True: raise ValueError('Container native scope differs: '+flag)
    for flag in FALSE_FLAGS:
        if report.get(flag) is not False: raise ValueError('Container fixture boundary differs: '+flag)
    expected = scenarios(); rows = report.get('cases')
    if (len(expected) != case_count() or len({canonical(s) for s in expected}) != case_count()
            or not isinstance(rows,list) or len(rows) != case_count()):
        raise ValueError('Container matrix differs')
    checker = oracle()
    for row,scenario in zip(rows,expected): checker.validate_case(row,scenario)
