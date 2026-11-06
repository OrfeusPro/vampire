"""Worker-local admission for verified character selection and world keepalive."""
from contextlib import contextmanager
from contextvars import ContextVar
import copy
import importlib.util
from pathlib import Path
import re

PREFIX = 'bounded-world:'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
POLICIES = frozenset(('game-login-world-v1', 'world-selection-move-v1', 'periodic-ping-v1', 'initial-character-stats-v1', 'character-stat-notifications-v1', 'quest-observation-v1'))
_active = ContextVar('vampir_bounded_world', default=None)


def selected(value):
    return isinstance(value, str) and value.startswith(PREFIX)


def current(selector=None):
    active = _active.get()
    if active is None or (selector is not None and active['selected_profile'] != selector):
        raise ValueError('Bounded world requires its active verified scope')
    return copy.deepcopy(active)


def permits(source_sha256, policy):
    active = _active.get()
    return (active is not None and source_sha256 == SOURCE == active['source_sha256']
            and policy in POLICIES and policy in active['policies'])


def _load(selector_sha, root, workspace):
    path = Path(workspace) / 'phone-exit/bots/vampir-headless/bounded-world-profile.py'
    spec = importlib.util.spec_from_file_location('bounded_world_profile_loader', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_manifest(selector_sha, root=root, workspace=workspace)


@contextmanager
def scope(selector, *, root, workspace):
    if not selected(selector) or not re.fullmatch('[0-9a-f]{64}', selector[len(PREFIX):]):
        raise ValueError('Bounded world selector requires a full manifest SHA')
    from .runtime_admission import _active as prepared_scope
    from .bounded_creation_admission import _active as creation_scope
    from .bounded_entry_admission import scope as entry_scope
    if prepared_scope.get() is not None or creation_scope.get() is not None:
        raise ValueError('Cannot mix bounded world with creation or a prepared world bundle')
    active = _active.get()
    if active is not None:
        if selector != active['selected_profile']:
            raise ValueError('A worker cannot switch bounded world profiles')
        yield selector
        return
    profile = _load(selector[len(PREFIX):], root, workspace)
    with entry_scope(profile['entry']['selected_profile'], root=root, workspace=workspace):
        token = _active.set(profile)
        try:
            yield profile['selected_profile']
        finally:
            _active.reset(token)
