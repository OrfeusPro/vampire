"""Декларативные native drivers v2; принятые semantic engines не изменяются."""
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

HERE = Path(__file__).resolve().parent
RECIPE = 'native-drivers-v2'
CONTRACT = 'bounded-native-publication-v2'
FIELDS = {'schema', 'recipe_id', 'id', 'family', 'adapter', 'module_basename',
    'factory_kind', 'execution_kind', 'index_relative_path', 'publication_contract_id',
    'reviewed_rule_pointer', 'order'}
IDENTIFIER = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}')
SHA = re.compile(r'[0-9a-f]{64}')


def validate_descriptor(value):
    if not isinstance(value, dict) or set(value) != FIELDS or value.get('schema') != 2 or value.get('recipe_id') != RECIPE:
        raise ValueError('Invalid native v2 descriptor schema')
    if any(not isinstance(value[k], str) or not IDENTIFIER.fullmatch(value[k]) for k in ('id', 'family', 'adapter')):
        raise ValueError('Invalid native v2 descriptor identity')
    module = value['module_basename']
    if (not isinstance(module, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,127}', module)
            or value['factory_kind'] not in ('module', 'select-family', 'utf8-module')
            or value['execution_kind'] not in ('portable', 'lineage-only')
            or value['publication_contract_id'] != CONTRACT
            or type(value['order']) is not int or not 0 <= value['order'] < 65536):
        raise ValueError('Unknown native v2 factory/publication contract')
    relative = value['index_relative_path']
    if (not isinstance(relative, str) or '\\' in relative or ':' in relative
            or PurePosixPath(relative).is_absolute() or '..' in PurePosixPath(relative).parts
            or not re.fullmatch(r'generated-[a-z0-9-]+(?:/[a-z0-9-]+)*', relative)):
        raise ValueError('Native v2 index path escapes knowledge')
    pointer = value['reviewed_rule_pointer']
    if (not isinstance(pointer, dict) or set(pointer) != {'path', 'sha256'}
            or pointer['path'] != module + '.py' or not isinstance(pointer['sha256'], str)
            or not SHA.fullmatch(pointer['sha256'])):
        raise ValueError('Native v2 descriptor lacks exact reviewed module')
    utf8 = value['factory_kind'] == 'utf8-module'
    if utf8 != (value['execution_kind'] == 'lineage-only') or (utf8 and (
            value['family'] != 'utf8' or value['adapter'] != 'utf8-v1' or module != 'update-native-contexts')):
        raise ValueError('Native v2 UTF-8 execution contract differs')
    return value


def registry(index, knowledge):
    folder = Path(knowledge).resolve() / 'native-drivers-v2'
    paths = sorted(folder.glob('*.json'))
    if not 1 <= len(paths) <= 128:
        raise ValueError('Native v2 descriptor budget is 1..128')
    result = []
    identities = {key: set() for key in ('id', 'family', 'order', 'index_relative_path')}
    for path in paths:
        if path.resolve().parent != folder:
            raise ValueError('Native v2 descriptor escapes registry')
        raw = path.read_bytes()
        if len(raw) > 32768:
            raise ValueError('Native v2 descriptor exceeds budget')
        value = validate_descriptor(json.loads(raw))
        if path.stem != value['family']:
            raise ValueError('Native v2 descriptor filename differs')
        for key, seen in identities.items():
            if value[key] in seen:
                raise ValueError('Duplicate native v2 descriptor ' + key)
            seen.add(value[key])
        module = HERE / value['reviewed_rule_pointer']['path']
        if module.resolve().parent != HERE.resolve() or index.digest(module) != value['reviewed_rule_pointer']['sha256']:
            raise ValueError('Native v2 reviewed module changed')
        if path.read_bytes() != raw:
            raise ValueError('Native v2 descriptor changed while reading')
        result.append(dict(value, _descriptor=dict(path=str(path.resolve()), sha256=hashlib.sha256(raw).hexdigest())))
    if sorted(folder.glob('*.json')) != paths:
        raise ValueError('Native v2 registry changed while reading')
    return sorted(result, key=lambda row: row['order'])


def spec(descriptor):
    return {key: descriptor[key] for key in ('id', 'family', 'adapter')}


def tool(index, descriptor):
    module = index.extension(descriptor['module_basename'])
    return module.select(descriptor['family']) if descriptor['factory_kind'] == 'select-family' else module


def run(index, args, sha, journal, database, *, families=None, cache_only=False):
    registered = registry(index, args.knowledge)
    selection = set(families) if families is not None else None
    executable = [row for row in registered if row['execution_kind'] == 'portable']
    if selection is not None and (not selection or selection - {row['family'] for row in executable}):
        raise ValueError('Selected native v2 family is not registered for portable execution')
    publication = index.extension('native-publication-v2').begin(index, args, sha)
    declarations, checks, queue, selected = [], [], [], []

    def stage(name, inputs, action):
        def guarded():
            if cache_only:
                raise ValueError('Native v2 cache-only stage is missing: ' + name)
            return action()
        return journal.stage(name, inputs, guarded)

    for descriptor in executable:
        family = descriptor['family']
        if selection is not None and family not in selection:
            continue
        selected.append(family)
        model = tool(index, descriptor)
        declaration_spec = spec(descriptor)
        try:
            inputs = model.plan_inputs(index, args, sha)
            def plan_writer():
                try:
                    return model.discover(index, args, sha)
                except (ValueError, OSError, KeyError, StopIteration) as error:
                    return dict(state='requires_review', reason=str(error))
            plan = stage('native-plan-' + family, inputs, plan_writer)
            if plan['state'] != 'planned':
                raise ValueError(plan['reason'])
            contexts = dict(source_sha256=sha, contracts={descriptor['id']: dict(
                bindings={str(i): address for i, address in enumerate(plan['exports'])})})
            collector = index.extension('update-run-v2')
            # The collector has its own missing-only guard. In cache-only mode
            # no Ghidra action may run, even before this driver's next stage.
            class CollectorJournal:
                def __getattr__(self, name):
                    return getattr(journal, name)
                def stage(self, name, inputs, action):
                    return stage(name, inputs, action)
            exports = collector.collect_batches(index, index.extension('research-workflow'),
                CollectorJournal(), args, getattr(args, 'scoped_database', database), contexts, sha)
            def materialize():
                try:
                    return model.materialize(index, args, sha, plan, getattr(args, 'scoped_database', database))
                except ValueError as error:
                    return dict(checks=[], queue=[dict(family=family,
                        reason='native_adapter_requires_review', details=str(error))])
            material = stage('native-context-' + family,
                dict(source=sha, plan=plan, exports=exports, tools=model.tools()), materialize)
            declarations.extend(material['checks'])
            queue.extend(material['queue'])
            for declaration in material['checks']:
                def execute():
                    try:
                        return model.execute(index, args, sha, declaration)
                    except ValueError as error:
                        return dict(id=declaration['id'], state='requires_review', reason=str(error))
                outcome = stage('native-check-' + declaration['id'], dict(source=sha, declaration=declaration,
                    suite_runtime=index.extension('update-native-harness').runtime_inputs()), execute)
                if outcome['state'] == 'passed':
                    publication.publish(declaration_spec, model, declaration, outcome)
                checks.append(outcome)
        except (ValueError, OSError, KeyError, StopIteration) as error:
            queue.append(dict(family=family, reason='native_adapter_requires_review', details=str(error)))
    metrics = publication.finish()
    return dict(declarations=declarations, checks=checks, queue=queue, families=selected,
        descriptors=[copy.deepcopy(row) for row in registered if row['family'] in selected], publication_cache=metrics)


def merge(native, checks, extra):
    covered = set(extra['families'])
    queue = []
    for original in native['queue']:
        item = copy.deepcopy(original)
        if item.get('family') in covered:
            continue
        if item.get('reason') == 'unregistered_native_suite_families':
            item['families'] = [name for name in item['families'] if name not in covered]
            if not item['families']:
                continue
        queue.append(item)
    native['queue'] = queue + extra['queue']
    native['checks'].extend(extra['declarations'])
    checks.extend(extra['checks'])
    native['publication_cache'] = extra['publication_cache']
    descriptors = {row['family']: row for row in extra['descriptors']}
    for row in native.get('family_coverage', []):
        if row['family'] in covered:
            row.update(adapter=descriptors[row['family']]['adapter'], reason='')
