"""Track our incoming server XY target, retaining the last known Z. No engine claim."""
from .character_move_event import decode_move_notify
from .character_select_result import CharacterSelectResultBody, WireVector3
from .world_entry_flow import ServerTargetPosition
from .world_move_start import SOURCE_SHA256


class CharacterTargetTracker:
    def __init__(self, selection, position, *, source_sha256):
        if source_sha256 != SOURCE_SHA256:
            raise ValueError('Unsupported target tracker source')
        if not isinstance(selection, CharacterSelectResultBody) or selection.result_code != 0:
            raise ValueError('Accepted character selection required')
        if not isinstance(position, ServerTargetPosition) or position.source != 'world_move_finish_result':
            raise ValueError('Initial world finish position required')
        position.vector.finite_values()
        key = selection.player.at(8)
        if type(key) is not int or not 0 <= key < 2**64:
            raise ValueError('Invalid selected character key')
        # Zero is not sufficient to establish an existing actor identity.
        self._key = key or None
        self.position = position
        self.revision = 1
        self.update_count = 0

    def __repr__(self): return 'CharacterTargetTracker(data=<redacted>)'

    def receive(self, body):
        if self.position is None: raise ValueError('Target tracker is closed')
        event = decode_move_notify(body, source_sha256=SOURCE_SHA256)
        if self._key is None or event.entity_key != self._key: return False
        event.finite_xy()
        vector = WireVector3((*event.xy_bits, self.position.vector.bits[2]))
        self.position = ServerTargetPosition(self.position.world_id, vector,
            source='character_move_notify_xy_retained_z')
        self.revision += 1
        self.update_count += 1
        return True

    def close(self):
        self._key = self.position = None
