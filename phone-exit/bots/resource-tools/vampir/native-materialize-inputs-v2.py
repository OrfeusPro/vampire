"""Exact reviewed code inputs for static native context materialization only."""
import copy
import hashlib
import json
from pathlib import Path
import re

RECIPE = 'native-materialize-inputs-v2'
NATIVE_TOOLS = (
    'update-native-contexts.py', 'native-release-registry.py',
    'function-reuse-plan.py', 'knowledge-index.py', 'research-workflow.py',
    'verify-utf8-context.py', 'update-native-harness.py', 'update-bindings.py',
    'build-native-entry-code.py', 'build-object-zero-init-code.py',
    'extract-native-enums.py')
# Reuse the portable runtime identity without changing any frozen proof engine.
TOOLS = NATIVE_TOOLS + ('stage-action-tools-v1.py',)


def scope(index, knowledge):
    here = Path(index.HERE).resolve()
    path = Path(knowledge)/'native-materialize-inputs.json'
    with path.open('rb') as stream:
        raw = stream.read(8193)
    if len(raw) > 8192:
        raise ValueError('Native materialize inputs exceed budget')
    rule = json.loads(raw)
    if (not isinstance(rule, dict) or set(rule) != {'schema', 'recipe', 'reviewed_tools'}
            or type(rule['schema']) is not int or rule['schema'] != 1
            or rule['recipe'] != RECIPE or not isinstance(rule['reviewed_tools'], dict)
            or set(rule['reviewed_tools']) != set(TOOLS)
            or any(not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value)
                for value in rule['reviewed_tools'].values())):
        raise ValueError('Unknown native materialize inputs recipe')
    actual = {str(here/name):index.digest(here/name) if (here/name).is_file() else None
        for name in TOOLS}
    reviewed = (Path(knowledge).resolve() == (here/'knowledge').resolve()
        and all(actual[str(here/name)] == sha for name, sha in rule['reviewed_tools'].items()))
    return dict(recipe=RECIPE, mode='reviewed' if reviewed else 'conservative', files=actual,
        recipe_guard={str(path.resolve()):hashlib.sha256(raw).hexdigest(),
            str(Path(__file__).resolve()):index.digest(Path(__file__))})


def tool_inputs(index, knowledge, legacy, native_runtime):
    value = scope(index, knowledge)
    value['portable_runtime'] = index.extension('stage-action-tools-v1').runtime(index)
    value['native_runtime'] = copy.deepcopy(native_runtime)
    registry = Path(index.HERE)/'knowledge/native-release-registry.json'
    value['native_registry'] = {str(registry.resolve()):index.digest(registry) if registry.is_file() else None}
    if value['mode'] != 'reviewed':
        value['legacy_tools'] = copy.deepcopy(legacy)
    return value


def definitions(index, args, inputs):
    value = scope(index, args.knowledge)
    if value['mode'] != 'reviewed':
        return inputs
    here = Path(index.HERE).resolve()
    bots = here.parents[1]
    allowed = {here/name for name in (*TOOLS, 'update-run.py', Path(__file__).name)}
    check_registry = (args.knowledge/'research-checks.json').resolve()
    result = {}
    for filename, sha in inputs.items():
        path = Path(filename).resolve()
        if path == check_registry:
            continue
        if path.is_relative_to(bots) and path.suffix == '.py' and path not in allowed:
            continue
        result[filename] = sha
    return result
