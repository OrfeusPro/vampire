"""An explicit immutable SDK-only scope, independent of world-session admission."""
from contextlib import contextmanager
from contextvars import ContextVar
import copy
import importlib.util
from pathlib import Path
import re

PREFIX = 'sdk-launcher:'
POLICY = 'sdk-launcher-gmc2-geo-v2'
_active = ContextVar('vampir_sdk_launcher_scope', default=None)


def selected(value):
    return isinstance(value, str) and value.startswith(PREFIX)


def current(selector):
    value = _active.get()
    if value is None or value['selector'] != selector:
        raise ValueError('SDK-only profile requires its explicit admitted scope')
    return copy.deepcopy(value['profile'])


def permits(source_sha256, policy):
    value = _active.get()
    return value is not None and policy == POLICY and source_sha256 == value['profile']['source_sha256']


@contextmanager
def scope(selector, *, root, workspace):
    if not selected(selector) or not re.fullmatch('[0-9a-f]{64}', selector[len(PREFIX):]):
        raise ValueError('SDK-only selector requires the full immutable profile SHA')
    from .runtime_admission import _active as world_scope
    if world_scope.get() is not None:
        raise ValueError('Cannot switch a world worker to an SDK-only profile')
    active = _active.get()
    if active is not None:
        if active['selector'] != selector:
            raise ValueError('Cannot switch SDK-only profiles within a worker')
        yield selector
        return
    path = Path(workspace) / 'phone-exit/bots/vampir-headless/sdk-launcher-profile.py'
    spec = importlib.util.spec_from_file_location('sdk_only_profile_loader', path)
    loader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loader)
    # Source identity comes from the exact content-addressed manifest; the loader
    # then checks the installed EXE and all 98 retained evidence inputs.
    manifest = Path(root) / 'sdk-launcher-profiles' / selector[len(PREFIX):] / 'manifest.json'
    if loader.digest(manifest, loader.MAX_MANIFEST) != selector[len(PREFIX):]:
        raise ValueError('SDK-only manifest changed')
    import json
    profile = json.loads(manifest.read_bytes())
    profile = loader.load_manifest(profile_sha256=selector[len(PREFIX):],
        source_sha256=profile['source_sha256'], root=root, workspace=workspace)
    token = _active.set(dict(selector=selector, profile=profile))
    try:
        yield selector
    finally:
        _active.reset(token)
