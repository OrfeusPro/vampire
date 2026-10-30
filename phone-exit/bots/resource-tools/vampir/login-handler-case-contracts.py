"""Exact continuation/reset and pre-gate Login error report contracts."""
import hashlib
import itertools
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAMILIES = ('login-continuation', 'login-handler-early')
COUNTS = dict(zip(FAMILIES, (8, 14)))
TOOLS = ('login-handler-case-contracts.py', 'verify-login-continuation-portable.py',
         'verify-login-handler-early-context.py', 'update-native-harness.py')
LEVELS = (0xf0, 0x140, 0x190, 0x210, 0x260, 0x2b0, 0x300)
VALUES = LEVELS + (0x1a0, 0x1b0, 0x220, 0x240, 0x244, 0x248, 0x24c, 0x270, 0x290, 0x294,
                    0x298, 0x29c, 0x2c0, 0x2e0, 0x2e4, 0x2e8, 0x2ec, 0x338, 0x33c)
BASE_WRITES = ((202, 0x1a0, 4, 0), (241, 0x1b0, 4, 0), (345, 0x220, 4, 0),
    (369, 0x248, 4, 0xffffffff), (376, 0x24c, 4, 0), (387, 0x240, 4, 0),
    (456, 0x270, 4, 0), (480, 0x298, 4, 0xffffffff), (487, 0x29c, 4, 0), (498, 0x290, 4, 0),
    (567, 0x2c0, 4, 0), (591, 0x2e8, 4, 0xffffffff), (598, 0x2ec, 4, 0), (609, 0x2e0, 4, 0),
    (663, 0x308, 2, 0), (733, 0x1a0, 4, 0), (765, 0x1b0, 4, 0),
    (806, 0x33c, 4, 0), (813, 0x338, 4, 0))
LEVEL_WRITES = ((70, 0xf0, 4, 1), (125, 0x140, 4, 1), (180, 0x190, 4, 1),
                (304, 0x210, 4, 1), (415, 0x260, 4, 1), (526, 0x2b0, 4, 1), (637, 0x300, 4, 1))
CAPACITY_WRITES = ((395, 0x244, 4, 128), (506, 0x294, 4, 128), (617, 0x2e4, 4, 128))
LOW_EVENTS = ((43, 0xa8), (53, 0xa8), (98, 0xf8), (108, 0xf8), (153, 0x148), (163, 0x148),
    (236, None), (277, 0x1c8), (287, 0x1c8), (335, 0x218), (446, 0x268), (557, 0x2b8),
    (671, 0x310), (760, None))
# Each high-level branch has its own call to the same clear helper. For example,
# JG at +41 enters +60 and calls at +62; the low branch calls at +53 and skips it.
HIGH_EVENTS = ((62, 0xa8), (77, 0xa8), (117, 0xf8), (132, 0xf8), (172, 0x148), (187, 0x148),
    (236, None), (296, 0x1c8), (311, 0x1c8), (422, 0x218), (533, 0x268), (644, 0x2b8),
    (671, 0x310), (760, None))
CAPACITY_EVENTS = ((402, 0x228), (513, 0x278), (624, 0x2c8))


def tools():
    return {str(HERE / name): hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in TOOLS}


def case_count(family):
    if not isinstance(family, str) or family not in COUNTS:
        raise ValueError('Unreviewed Login handler family')
    return COUNTS[family]


def verifier(family):
    case_count(family)
    return 'verify-login-continuation-portable' if family == FAMILIES[0] else 'verify-login-handler-early-context'


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def continuation_case(level, capacity, context):
    values = {hex(at): min(level, 1) if at in LEVELS else 0 for at in VALUES}
    values.update({hex(at): 128 for at in (0x244, 0x294, 0x2e4)})
    values.update({hex(at): 0xffffffff for at in (0x248, 0x298, 0x2e8)})
    writes = sorted(BASE_WRITES + (LEVEL_WRITES if level > 1 else ()) + (CAPACITY_WRITES if capacity > 128 else ()))
    events = sorted((HIGH_EVENTS if level > 1 else LOW_EVENTS) + (CAPACITY_EVENTS if capacity > 128 else ()))
    return dict(level=level, capacity=capacity, ctor_vptrs=[int(context['base_table'], 16), int(context['table'], 16)],
        values=values, field308=0, flag=0, guards=True, abi=True, constructor_guards=True,
        events=[dict(call_offset=at, offset=hex(offset) if offset is not None else None, second=0) for at, offset in events],
        writes=[dict(phase='reset', instruction_offset=at, offset=hex(offset), size=size, value=value)
                for at, offset, size, value in writes])


def early_events(code, present):
    result = [('string_init', 45), ('log', 103)]
    if code == 54:
        result += [('string_init', 1451), ('localizer', 1456), ('localized', 1472), ('popup54', 1491)]
    elif code in (9818, 9819):
        result += [('optional_9818', 1351)] + ([('optional_prepare', 1367), ('error_9818', 1377)] if present else []) + [('error_finish', 1384)]
    else:
        # A null lookup takes JZ +1329 -> +1382, sharing the finish call at
        # +1384 with the 9818/9819 branch. The present path finishes at +1341.
        result += [('optional_90021', 1321)] + ([('error_90021', 1334)] if present else []) + [('error_finish', 1341 if present else 1384)]
    return [dict(action=action, call_offset=at, arguments_checked=True) for action, at in result]


def expected_rows(family, context):
    """Pure fixture oracle; only source-bound native execution creates evidence."""
    case_count(family)
    if family == FAMILIES[0]:
        return [continuation_case(level, capacity, context) for level, capacity in itertools.product((0, 1, 2, 5), (128, 256))]
    return [dict(code=code, optional_present=present, poison=poison,
                 events=early_events(code, present), guards=True, abi=True)
            for poison in (0x55, 0xaa) for code, present in ([(54, False)] + [
                (code, present) for code, present in itertools.product((9818, 9819, 90021), (False, True))])]


def validate_report(family, report, context=None):
    count = case_count(family)
    if not isinstance(context, dict):
        raise ValueError('Login handler report requires the checked source context')
    if (not isinstance(report, dict) or type(report.get('schema')) is not int or report['schema'] != 1
            or report.get('method') != 'bounded_native'):
        raise ValueError('Login handler report schema/method differs')
    for flag in ('network_used', 'profile_activated', 'runtime_activated', 'gate_executed', 'successful_login_executed'):
        if report.get(flag) is not False:
            raise ValueError('Login handler scope/activation flag differs')
    expected = expected_rows(family, context)
    if len(expected) != count or canonical(report.get('cases')) != canonical(expected):
        raise ValueError('Login handler matrix/outcome differs')
    if family == FAMILIES[1] and report.get('handler') != context['functions']['handler']:
        raise ValueError('Login handler report root differs')
