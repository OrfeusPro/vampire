"""Проверенные инструменты отдельных действий обновлятора и их runtime."""
import copy
import ctypes
import dataclasses
import encodings.utf_8_sig
import hashlib
import json
import locale
from pathlib import Path
import re
import sys
import urllib.parse

RECIPE = 'stage-action-tools-v1'
COMMON = (
    'update-native-harness.py', 'update-bindings.py', 'build-native-entry-code.py',
    'build-object-zero-init-code.py', 'extract-native-enums.py',
    'audit-launcher-shape-11318.py', 'update-native-contexts.py',
    'function-reuse-plan.py', 'native-release-registry.py', 'research-workflow.py',
    'knowledge-index.py', 'knowledge-context.py', 'verify-utf8-context.py')
ROLES = {
    'context-tag': COMMON + ('verify-version-login-context.py',),
    'context-writer': COMMON + ('verify-packet-writer-context.py',),
    'profile-builder': ('update-profile.py', 'knowledge-index.py', 'research-workflow.py')}
SHARED = ('__init__.py', 'sdk_config.py', 'gmc2_request.py')


def files(here, role):
    paths = [here/name for name in ROLES[role]]
    if role == 'profile-builder':
        paths.extend(here.parents[1]/'vampir-shared/vampir_core'/name for name in SHARED)
    return paths


def runtime(index):
    paths = {Path(sys.executable).resolve()}
    for module in (dataclasses, urllib.parse, ctypes, locale, encodings.utf_8_sig):
        paths.add(Path(module.__file__).resolve())
    for name in ('_ctypes', '_locale', '_hashlib', '_json'):
        filename = getattr(sys.modules.get(name), '__file__', None)
        if filename:
            paths.add(Path(filename).resolve())
    for parent in (Path(sys.base_prefix), Path(sys.base_prefix)/'DLLs'):
        for name in (f'python{sys.version_info.major}{sys.version_info.minor}.dll', 'python3.dll'):
            path = parent/name
            if path.is_file():
                paths.add(path.resolve())
    return dict(python=sys.version, implementation=sys.implementation.name,
        files={str(path):index.digest(path) for path in sorted(paths)})


def inputs(index, knowledge, groups, native_runtime):
    path = Path(knowledge)/'stage-action-tools.json'
    if not path.is_file():
        return {}
    with path.open('rb') as stream:
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError('Stage action tools registry exceeds budget')
    rule = json.loads(raw)
    if (not isinstance(rule, dict) or set(rule) != {'schema', 'recipe', 'roles'}
            or type(rule['schema']) is not int or rule['schema'] != 1
            or rule['recipe'] != RECIPE or not isinstance(rule['roles'], dict)
            or set(rule['roles']) != set(ROLES)):
        raise ValueError('Unknown stage action tool recipe')
    here = Path(index.HERE).resolve()
    workspace = here.parents[3]
    guard = {str(path.resolve()):hashlib.sha256(raw).hexdigest(),
        str(Path(__file__).resolve()):index.digest(Path(__file__))}
    portable = runtime(index)
    result = {}
    for role in ROLES:
        declared = rule['roles'][role]
        paths = files(here, role)
        names = {p.relative_to(workspace).as_posix() for p in paths}
        if (not isinstance(declared, dict) or set(declared) != names
                or any(not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{64}', sha)
                    for sha in declared.values())):
            raise ValueError('Incomplete stage action tools: '+role)
        actual = {str(p.resolve()):index.digest(p) if p.is_file() else None for p in paths}
        reviewed = (Path(knowledge).resolve() == (here/'knowledge').resolve()
            and all(actual[str(p.resolve())] == declared[p.relative_to(workspace).as_posix()] for p in paths))
        value = dict(recipe=RECIPE, role=role, mode='reviewed' if reviewed else 'conservative',
            files=actual, recipe_guard=guard, portable_runtime=portable)
        if role.startswith('context-'):
            registry = here/'knowledge/native-release-registry.json'
            value['native_registry'] = {str(registry.resolve()):index.digest(registry) if registry.is_file() else None}
            value['native_runtime'] = copy.deepcopy(native_runtime)
        if not reviewed:
            value['legacy_tools'] = copy.deepcopy(groups['profile' if role == 'profile-builder' else 'context'])
        result[role] = value
    return result
