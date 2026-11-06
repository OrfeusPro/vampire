"""Current lobby login binding with retained VersionResult metadata.

This module performs no SDK/provider/network IO. The connection owner must keep
the returned binding with its exact source/profile, and supply a separately
admitted decoder/transport. Raw +40/+50/+54 fields are retained, never treated
as applied timezone/engine state by this pure Windows flag-off binder.
"""
from dataclasses import dataclass, field

from .login_packet import _numbers, _utf8
from .lobby_packets import (
    CURRENT_LOBBY_VERSION_SOURCE,
    CurrentLobbyVersionResultBody,
    LobbyLoginPayload,
)


@dataclass(frozen=True, slots=True)
class CurrentWindowsLobbyLoginBinding:
    login: LobbyLoginPayload = field(repr=False)
    version_result: CurrentLobbyVersionResultBody = field(repr=False)
    source_sha256: str
    metadata_applied: bool = field(default=False, init=False)

    def __post_init__(self):
        if self.source_sha256 != CURRENT_LOBBY_VERSION_SOURCE:
            raise ValueError('Current lobby login binding source is not verified')
        if not isinstance(self.login, LobbyLoginPayload) or not isinstance(self.version_result, CurrentLobbyVersionResultBody):
            raise TypeError('Expected current VersionResult and explicit lobby Login')
        if self.version_result.result_code != 0:
            raise ValueError('Current lobby Version did not succeed')
        if self.version_result.flag_14:
            raise NotImplementedError('Current Version flag requires additional numeric context')


def make_current_windows_lobby_login(*, version_result, kind, selected_server_id, metadata, source_sha256):
    """Bind only the previously proven Windows flag-off numbers, on exact SHA.

    Keep the complete current result alongside the outgoing Login. The source
    handler's metadata validation/application needs an actual provider policy;
    preserving these fields does not claim that policy or change OS/engine state.
    The SDK owner separately binds the first five strings with current identity.
    """
    if source_sha256 != CURRENT_LOBBY_VERSION_SOURCE:
        raise ValueError('Current lobby login binding source is not verified')
    if not isinstance(version_result, CurrentLobbyVersionResultBody):
        raise TypeError('Expected separate current lobby VersionResult')
    if version_result.result_code != 0:
        raise ValueError('Current lobby Version did not succeed')
    if version_result.flag_14:
        raise NotImplementedError('Current Version flag requires additional numeric context')
    _numbers((kind, selected_server_id), 2, 0xffffffff)
    _utf8(metadata)
    login = LobbyLoginPayload(('',) * 5 + (metadata,),
        (2, 2 if kind == 2 else 0, selected_server_id, 0), 7)
    return CurrentWindowsLobbyLoginBinding(login, version_result, source_sha256)
