"""Worker-local admission for one current Create on an accepted empty list."""
from contextlib import contextmanager
from contextvars import ContextVar
import copy
import importlib.util
from pathlib import Path
import re

PREFIX = 'bounded-create:'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
POLICY = 'character-create-current-v1'
_active = ContextVar('vampir_bounded_creation', default=None)


def selected(value):
    return isinstance(value, str) and value.startswith(PREFIX)


def current(selector=None):
    active = _active.get()
    if active is None or (selector is not None and active['selected_profile'] != selector):
        raise ValueError('Bounded creation requires its active verified scope')
    return copy.deepcopy(active)


def permits(source_sha256, policy=POLICY):
    active = _active.get()
    return (active is not None and source_sha256 == SOURCE == active['source_sha256']
            and policy == POLICY == active['policy'])


def _load(selector_sha, root, workspace):
    path = Path(workspace) / 'phone-exit/bots/vampir-headless/bounded-creation-profile.py'
    spec = importlib.util.spec_from_file_location('bounded_creation_profile_loader', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_manifest(selector_sha, root=root, workspace=workspace)


@contextmanager
def scope(selector, *, root, workspace):
    if not selected(selector) or not re.fullmatch('[0-9a-f]{64}', selector[len(PREFIX):]):
        raise ValueError('Bounded creation selector requires a full manifest SHA')
    active = _active.get()
    if active is not None:
        if selector != active['selected_profile']:
            raise ValueError('A worker cannot switch bounded creation profiles')
        yield selector
        return
    from .runtime_admission import _active as world_scope
    from .bounded_world_admission import _active as bounded_world_scope
    from .bounded_entry_admission import scope as entry_scope
    if world_scope.get() is not None or bounded_world_scope.get() is not None:
        raise ValueError('Cannot mix world and bounded creation profiles')
    profile = _load(selector[len(PREFIX):], root, workspace)
    with entry_scope(profile['entry']['selected_profile'], root=root, workspace=workspace):
        token = _active.set(profile)
        try:
            yield profile['selected_profile']
        finally:
            _active.reset(token)
