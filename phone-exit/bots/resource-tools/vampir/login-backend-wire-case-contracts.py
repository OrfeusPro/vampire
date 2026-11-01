"""Explicit inputs for the next bounded Login backend/wire experiment.

This module defines expectations only. It cannot publish native evidence, admit
a runtime profile or claim that the 1807 cases have executed.
"""
import copy
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAMILY = 'login-backend-wire'
SCOPE = 'bounded_native_login_backend_wire'
CHECKSUM_FIXTURE = 0x6a09e667
DEBUG_CASES = ('off', 'firsttrue', 'secondtrue')
BACKEND_CASES = {
    'serialize': (0, 1, 0, 0),
    'globaldisabled': (1, 1, 0, 0),
    'mode2action': (0, 2, 0, 0),
    'mode2quiet': (0, 2, 0, 1),
    'mode2action-otherflag': (0, 2, 0, 2),
    'backendbusy': (0, 1, 1, 0),
}
GATE_FIELDS = ('global_disabled', 'backend_state', 'backend_busy', 'backend_mode')
DIMENSIONS = ('group', 'prepared_ordinal', 'transport_result_byte', 'sequence_seed',
    'debug_case', 'backend_case', *GATE_FIELDS)
FOCUSED = (
    ('windows-all', False, ['shared', 'unicode-quote', True]),
    ('windows-all', True, ['ready', 'empty', True]),
    ('sdk-disabled', False, ['ready', 'full', False]),
)


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PARENT = load('login-send-handoff-case-contracts')


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def tools():
    return {**PARENT.tools(), **{str(HERE / n): hashlib.sha256((HERE / n).read_bytes()).hexdigest()
        for n in ('login-backend-wire-case-contracts.py', 'login-backend-wire-oracle.py')}}


def prepared_specs():
    return [dict(scenario=scenario[0], selector=3, empty=empty, poison=0x55,
                 cache_case='warm', metadata_case=list(metadata))
        for scenario, empty, metadata in itertools.product(
            PARENT.PREPARE.SCENARIOS, (False, True), PARENT.PARENT.INTEGRATION_CASES)]


def _spec(base, ordinal, pending, result, case, group, sequence, debug):
    return dict(copy.deepcopy(base), group=group, prepared_ordinal=ordinal,
        pending_case=pending, transport_result_byte=result, sequence_seed=sequence,
        debug_case=debug, backend_case=case, **dict(zip(GATE_FIELDS, BACKEND_CASES[case])))


def scenarios():
    prepared = prepared_specs()
    rows = [_spec(base, i, pending, result, 'serialize', 'core',
                 (0, 0xfffe, 0xffff)[i % 3], DEBUG_CASES[(i // 3) % 3])
        for i, base in enumerate(prepared)
        for pending, result in itertools.product(PARENT.PENDING_CASES, (0, 1))]
    for example, (scenario, empty, metadata) in enumerate(FOCUSED):
        candidates = [(i, base) for i, base in enumerate(prepared)
            if (base['scenario'], base['empty'], base['metadata_case']) == (scenario, empty, metadata)]
        if len(candidates) != 1:
            raise ValueError('Backend focused prepared input is missing or ambiguous')
        i, base = candidates[0]
        rows.extend(_spec(base, i, PARENT.PENDING_CASES[0], 0, case,
                          'focused-negative', (0, 0xfffe, 0xffff)[example], 'off')
            for case in BACKEND_CASES if case != 'serialize')
    return rows


def case_count():
    return 1807


def validate_spec(spec):
    if not isinstance(spec, dict) or set(spec) != set(PARENT.SPEC_FIELDS) | set(DIMENSIONS):
        raise ValueError('Backend wire input fields differ')
    PARENT.validate_spec({k: spec[k] for k in PARENT.SPEC_FIELDS})
    for field in ('prepared_ordinal', 'transport_result_byte', 'sequence_seed', *GATE_FIELDS):
        if type(spec[field]) is not int:
            raise ValueError('Backend wire input integer differs: ' + field)
    i = spec['prepared_ordinal']
    prepared = prepared_specs()
    if not 0 <= i < len(prepared) or any(spec[k] != v or type(spec[k]) is not type(v)
            for k, v in prepared[i].items()):
        raise ValueError('Backend prepared ordinal differs')
    case = spec['backend_case']
    if (not isinstance(case, str) or case not in BACKEND_CASES
            or tuple(spec[k] for k in GATE_FIELDS) != BACKEND_CASES[case]
            or spec['transport_result_byte'] not in (0, 1)):
        raise ValueError('Backend gate/transport policy differs')
    if spec['group'] == 'core':
        if (case != 'serialize' or spec['sequence_seed'] != (0, 0xfffe, 0xffff)[i % 3]
                or spec['debug_case'] != DEBUG_CASES[(i // 3) % 3]):
            raise ValueError('Backend core recipe differs')
    elif spec['group'] == 'focused-negative':
        focus = (spec['scenario'], spec['empty'], spec['metadata_case'])
        if focus not in FOCUSED:
            raise ValueError('Backend focused input differs')
        if (case == 'serialize' or spec['sequence_seed'] != (0, 0xfffe, 0xffff)[FOCUSED.index(focus)] or spec['debug_case'] != 'off'
                or spec['pending_case'] != PARENT.PENDING_CASES[0] or spec['transport_result_byte'] != 0
                ):
            raise ValueError('Backend focused recipe differs')
    else:
        raise ValueError('Backend matrix group differs')
    return spec


def expected_flow(spec):
    """Source branch expectations, independent of the future runtime observer."""
    validate_spec(spec)
    entered = PARENT.pending_settings(spec['pending_case'])['forwarded']
    state_read = entered and not spec['global_disabled']
    ready = state_read and spec['backend_state'] != 2 and not spec['backend_busy']
    fallback = state_read and not ready and spec['backend_mode'] != 1 and not spec['backend_busy']
    debug = spec['debug_case']
    n = int(ready)
    return dict(backend_calls=int(entered), state_getter_calls=int(state_read),
        fallback_calls=int(fallback), writer_calls=n, transport_calls=n,
        checksum_calls=n, transform_calls=n, archive_constructor_calls=2*n,
        archive_cleanup_calls=2*n, initial_growth_calls=2*n,
        debug_first_calls=n, debug_second_calls=n*int(debug != 'firsttrue'),
        request_id_calls=n*(1+int(debug != 'off')),
        sequence_before=spec['sequence_seed'],
        sequence_after=(spec['sequence_seed']+n) & 0xffff,
        backend_return_al=spec['transport_result_byte'] if ready else 0 if entered else None,
        diagnostic_words=[1, 0],
        selected_diagnostic_offset=(4 if debug == 'off' else 0) if ready else None,
        pending_suppressed=not entered)


def summary():
    specs = scenarios()
    if len(specs) != case_count() or len({canonical(s) for s in specs}) != case_count():
        raise ValueError('Backend exact matrix differs')
    flows = [expected_flow(s) for s in specs]
    keys = ('backend_calls', 'state_getter_calls', 'fallback_calls', 'writer_calls',
        'transport_calls', 'archive_constructor_calls', 'archive_cleanup_calls', 'initial_growth_calls')
    return dict(cases=len(specs), prepared_inputs=len(prepared_specs()),
        core=sum(s['group'] == 'core' for s in specs),
        focused_negative=sum(s['group'] == 'focused-negative' for s in specs),
        pending_suppressed=sum(f['pending_suppressed'] for f in flows),
        sequence_wraps=sum(f['writer_calls'] and f['sequence_after'] == 0 for f in flows),
        transport_result0=sum(f['transport_calls'] and f['backend_return_al'] == 0 for f in flows),
        transport_result1=sum(f['transport_calls'] and f['backend_return_al'] == 1 for f in flows),
        **{k: sum(f[k] for f in flows) for k in keys})
