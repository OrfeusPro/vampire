"""Capability-bound prepared runtime policy, local to one worker context.

The actual client SHA is retained. No historical source set or global decoder
setting is changed, and an immutable selector stays pinned for the owner life.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps
import hashlib
from pathlib import Path

ADAPTER_ID='portable-world-session-v1'
POLICIES=frozenset(('sdk-launcher-gmc2-geo-v2','lobby-ping-clock-v1','periodic-ping-v1',
    'world-selection-move-v1','game-login-world-v1'))
CONSUMERS=tuple('phone-exit/bots/'+name for name in (
    'vampir-shared/vampir_core/runtime_admission.py',
    'vampir-shared/vampir_core/gmc2_context.py',
    'vampir-shared/vampir_core/session_clock.py',
    'vampir-shared/vampir_core/heartbeat.py',
    'vampir-shared/vampir_core/world_move_start.py',
    'vampir-shared/vampir_core/world_entry_flow.py',
    'vampir-shared/vampir_core/world_reserve_context.py',
    'vampir-shared/vampir_core/game_login_probe.py',
    'vampir-shared/vampir_core/game_connection.py',
    'vampir-shared/vampir_core/live_session.py',
    'vampir-headless/game-source-profile.py',
    'vampir-headless/sdk-source-profile.py',
    'vampir-headless/run-live-sessions.py',
    'vampir-headless/probe-selected-game-login.py',
    'vampir-headless/probe-lobby-sdk-login.py',
    'vampir-headless/run-nid-sdk-sign-in.py'))
CONSUMERS+=('phone-exit/bots/test_vampir_prepared_runtime.py',)
_active=ContextVar('vampir_prepared_runtime_admission',default=None)


def is_prepared(selected):
    return isinstance(selected,str) and (selected=='prepared-next' or selected.startswith('prepared:'))


def descriptor(workspace):
    workspace=Path(workspace).resolve()
    return dict(id=ADAPTER_ID,capability='world-session',policies=sorted(POLICIES),consumers={
        name:hashlib.sha256((workspace/name).read_bytes()).hexdigest() for name in CONSUMERS})


@dataclass(frozen=True,slots=True)
class _Admission:
    selector:str
    source_sha256:str
    bundle:dict


def pin(selected,*,root,workspace):
    if not is_prepared(selected):return selected
    from .release_bundle import validate
    bundle=validate(root=root,workspace=workspace,selected=selected,capability='world-session')
    if bundle.get('runtime_adapter')!=descriptor(workspace):
        raise ValueError('Prepared runtime adapter is missing or changed')
    return bundle['selected_profile']


def current_bundle(selected):
    active=_active.get()
    if active is None or selected!=active.selector:return None
    # Callers may read profile fields, never mutate the admitted object.
    import copy
    return copy.deepcopy(active.bundle)


def permits(source_sha256,policy):
    active=_active.get()
    return (active is not None and policy in POLICIES and type(source_sha256) is str
        and source_sha256==active.source_sha256)


@contextmanager
def profile_scope(selected,*,root,workspace):
    if not is_prepared(selected):
        yield selected;return
    active=_active.get()
    if active is not None:
        if selected not in ('prepared-next',active.selector):
            raise ValueError('A worker cannot switch prepared runtime bundles')
        yield active.selector;return
    from .release_bundle import validate
    bundle=validate(root=root,workspace=workspace,selected=selected,capability='world-session')
    if bundle.get('runtime_adapter')!=descriptor(workspace):
        raise ValueError('Prepared runtime adapter is missing or changed')
    admission=_Admission(bundle['selected_profile'],bundle['source_sha256'],bundle)
    token=_active.set(admission)
    try:yield admission.selector
    finally:_active.reset(token)


def prepared_entrypoint(*,root,workspace,keyword='selected_profile'):
    """Enter once before IO; nested calls reuse that exact immutable selector."""
    def decorate(function):
        @wraps(function)
        def call(*args,**kwargs):
            selected=kwargs.get(keyword)
            if not is_prepared(selected):return function(*args,**kwargs)
            with profile_scope(selected,root=root,workspace=workspace) as pinned:
                return function(*args,**{**kwargs,keyword:pinned})
        return call
    return decorate


def bind_worker(function):
    """Capture one admitted bundle for a worker; do not share global state."""
    admission=_active.get()
    @wraps(function)
    def run(*args,**kwargs):
        if admission is None:return function(*args,**kwargs)
        current=_active.get()
        if current is not None and current is not admission:
            raise ValueError('Worker already belongs to a different runtime admission')
        token=_active.set(admission)
        try:return function(*args,**kwargs)
        finally:_active.reset(token)
    return run
