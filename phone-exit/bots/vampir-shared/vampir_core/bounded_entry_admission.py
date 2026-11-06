"""A worker-local immutable admission limited to fresh character-list entry."""
from contextlib import contextmanager
from contextvars import ContextVar
import copy
import importlib.util
from pathlib import Path
import re

PREFIX = 'bounded-entry:'
_active = ContextVar('vampir_bounded_entry', default=None)


def selected(value):
    return isinstance(value, str) and value.startswith(PREFIX)


def current(selector=None):
    active = _active.get()
    if active is None or (selector is not None and selector != active['selected_profile']):
        raise ValueError('Bounded entry requires its active verified scope')
    return copy.deepcopy(active)


def permits(source_sha256, policy):
    active = _active.get()
    return active is not None and active['source_sha256'] == source_sha256 and policy in active['policies']


@contextmanager
def scope(selector, *, root, workspace):
    if not selected(selector) or not re.fullmatch('[0-9a-f]{64}', selector[len(PREFIX):]):
        raise ValueError('Bounded entry selector requires a full manifest SHA')
    active = _active.get()
    if active is not None:
        if selector != active['selected_profile']:
            raise ValueError('A worker cannot switch bounded entry profiles')
        yield selector
        return
    from .runtime_admission import _active as world_scope
    from .sdk_launcher_admission import scope as sdk_scope
    if world_scope.get() is not None:
        raise ValueError('Cannot mix a world bundle and bounded entry')
    path = Path(workspace) / 'phone-exit/bots/vampir-headless/bounded-entry-profile.py'
    spec = importlib.util.spec_from_file_location('bounded_entry_profile_loader', path)
    loader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loader)
    profile = loader.load_manifest(selector[len(PREFIX):], root=root, workspace=workspace)
    token = _active.set(profile)
    try:
        with sdk_scope('sdk-launcher:' + profile['sdk_profile_sha256'], root=root, workspace=workspace):
            yield profile['selected_profile']
    finally:
        _active.reset(token)


def require_character_list_operation(selector, *, auth_flow, read_character_list, character_index,
        server_list_only, creation_factory, read_world_start, read_world_finish, observe_world_seconds,
        world_observer, tutorial_observer, ack_initial_tutorial, read_quest_list, quest_observer,
        quest_wire_observer, session_control):
    current(selector)
    creation_allowed = False
    if creation_factory is not None:
        from .bounded_creation_admission import current as creation_current, permits as creation_permits
        parent = current(selector)
        if creation_permits(parent['source_sha256']):
            creation = creation_current()
            creation_allowed = (callable(creation_factory) and read_character_list
                and creation['entry']['selected_profile'] == selector)
    if (auth_flow != 'launcher' or not (read_character_list or server_list_only)
            or character_index is not None or (creation_factory is not None and not creation_allowed)
            or read_world_start or read_world_finish or observe_world_seconds or world_observer is not None
            or tutorial_observer is not None or ack_initial_tutorial or read_quest_list
            or quest_observer is not None or quest_wire_observer is not None or session_control is not None):
        raise ValueError('Bounded entry permits launcher login and character lists only')
