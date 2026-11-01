"""Pure expectations for actual native Login post-state and continuation flow.

Native observations are supplied by the runtime. Existing instruction-derived
child oracles are reused without their standalone stacks, returns or verifiers.
"""
import copy
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


DISPATCH = load('login-dispatch-oracle')
POST_STATE = load('post-state-case-contracts')
CONTINUATION = load('login-handler-case-contracts')


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def expected_post_state(settings, invoked):
    settings = dict(POST_STATE.DEFAULTS, **settings)
    # A zero synthetic origin keeps only instruction-relative store offsets.
    child = POST_STATE.expected_case(False, settings, dict(functions=dict(target='0x0')))
    reaches = bool(child['target_entry']) if invoked else False
    return dict(settings=settings, wrapper_calls=int(invoked), getter_calls=int(invoked) + int(reaches),
        target_entry=[dict(service=True, actor=True, flag=1, tail_stack_preserved=True)] if reaches else [],
        events=list(child['events']) if invoked else [],
        writes=[dict(offset=w['offset'], size=w['size'], value=w['value'], instruction_offset=int(w['instruction'], 16))
                for w in child['writes']] if invoked else [],
        slot=child['slot'] if invoked else 0xaabbccdd, guards=True, actor_unchanged=True,
        unrelated_service_unchanged=True, arguments_checked=True)


def expected_continuation(settings, invoked):
    level, capacity = settings['level'], settings['capacity']
    if type(level) is not int or level not in (0, 1, 2, 5) or type(capacity) is not int or capacity not in (128, 256):
        raise ValueError('State-flow continuation settings differ')
    child = CONTINUATION.continuation_case(level, capacity, dict(base_table='0x0', table='0x0'))
    if level <= 1:
        # The handler loads RDX from the source vtable before CALL [RDX+0x28].
        # Reset's low first helper at +43 precedes its first XOR EDX,EDX.
        # Runtime checks that full RDX is exactly the checked source vtable;
        # this symbolic projection preserves that observation across versions.
        first = child['events'][0]
        if first['call_offset'] != 43 or first['second'] != 0:
            raise ValueError('State-flow inherited low continuation event differs')
        first['second'] = 'source_vtable_low32'
    return dict(level=level, capacity=capacity, constructor_calls=1, getter_calls=int(invoked),
        reset_calls=int(invoked), ctor_vptrs=['base_table', 'table'], constructor_published_singleton=True,
        reset_via_source_vtable=bool(invoked), values=copy.deepcopy(child['values']) if invoked else None,
        field308=0 if invoked else 0xffff, flag=0 if invoked else 1,
        events=copy.deepcopy(child['events']) if invoked else [], writes=copy.deepcopy(child['writes']) if invoked else [],
        guards=True, abi=True, constructor_guards=True, unattributed_store=False,
        reset_state_unchanged=not invoked)


def expected_case(spec):
    if spec.get('kind') != 'delivery' or spec.get('group') not in ('state-flow', 'negative-handler', 'negative-reader'):
        raise ValueError('State-flow delivery kind/group differs')
    row = DISPATCH.expected_case(spec)
    handler = row['handler']
    invoked = handler is not None and any(event.get('action') == 'post_state' for event in handler['events'])
    if handler is not None:
        # These two former fixture observations are replaced by actual native
        # wrapper/getter/tail/reset projections, not renamed fixture successes.
        handler['events'] = [event for event in handler['events'] if event.get('action') not in ('post_state', 'virtual_view')]
    row.update(post_state=expected_post_state(spec['post_settings'], invoked),
        continuation=expected_continuation(spec['continuation_settings'], invoked),
        providers_prepared_before_delivery=True, continuation_reseeded_at_handler=False)
    return row


def validate_case(row, spec):
    if not isinstance(row, dict):
        raise ValueError('State-flow actual row differs')
    wanted = expected_case(spec)
    if canonical(row) != canonical(wanted):
        if set(row) != set(wanted):
            raise ValueError('State-flow case fields differ')
        for key in wanted:
            if canonical(row[key]) != canonical(wanted[key]):
                raise ValueError('State-flow case ' + key + ' differs')
        raise ValueError('State-flow case differs')
    return row
