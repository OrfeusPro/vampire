"""Pure owner-side quest selection and attempt fences; no packets or task guesses."""
import copy
import re


_ID = re.compile(r'[a-zA-Z0-9_-]{1,48}')
_SHA = re.compile(r'[a-f0-9]{64}')
_REQUEST = re.compile(r'[a-f0-9]{32}')
_DECIMAL = re.compile(r'(?:0|[1-9][0-9]{0,19})')
_REASONS = frozenset(('death', 'user_stop', 'unknown_result', 'stale_context',
                      'not_admitted', 'waiting_data', 'connection_lost'))
_CONTEXT_FIELDS = frozenset(('bot_id', 'session_id', 'character_key', 'world_id', 'source_sha256'))


def decimal(value):
    return type(value) is str and _DECIMAL.fullmatch(value) and int(value) <= 0xffffffffffffffff


def context(value):
    if (type(value) is not dict or set(value) != _CONTEXT_FIELDS
            or any(type(value[name]) is not str or not _ID.fullmatch(value[name]) for name in ('bot_id', 'session_id'))
            or not decimal(value['character_key'])
            or type(value['world_id']) is not int or not 0 <= value['world_id'] <= 0xffffffff
            or type(value['source_sha256']) is not str or not _SHA.fullmatch(value['source_sha256'])):
        raise ValueError('Explicit quest owner context required')
    return value.copy()


class QuestAutomation:
    """Serial owner state machine. The caller owns its lock and action queue.

    Selection is a preference, never action admission. Only an enabled, exact
    owner offer from observe() can be returned by next_offer(). No offer is
    inferred from quest IDs, coordinates, task kind, NPC names or UI controls.
    """
    def __init__(self):
        self._context = None
        self._selected = None
        self._enabled = False
        self._state = 'idle'
        self._reason = None
        self._cancel_pending = False
        self._pending = None
        self._offer = None
        self._alive = None
        self._connected = False
        self._unknown = False
        self._attempted = set()

    def snapshot(self):
        return dict(supported=True, selected_quest_id=self._selected, enabled=self._enabled,
                    state=self._state, stop_reason=self._reason, cancel_pending=self._cancel_pending,
                    pending_request_id=self._pending['request_id'] if self._pending else None)

    def take_cancel_pending(self):
        """Owner cancels only unsent queued intents; unknown receipts stay fenced."""
        value = self._cancel_pending
        self._cancel_pending = False
        return value

    def stop(self, reason='user_stop'):
        if reason not in _REASONS:
            raise ValueError('Unknown quest automation stop reason')
        self._enabled = False
        self._offer = None
        self._cancel_pending = True
        self._reason = reason
        if reason == 'unknown_result':
            self._unknown = True
        if reason == 'death':
            self._alive = False
        if reason in ('user_stop', 'stale_context', 'connection_lost'):
            self._selected = None
        if self._unknown:
            self._reason = 'unknown_result'
        self._state = ('unknown' if self._unknown else 'dead' if reason == 'death'
                       else 'idle' if reason == 'user_stop' else 'paused')
        return self.snapshot()

    def toggle(self, quest_id, *, enabled=None, owner_context=None, alive=None):
        """Set or toggle one selected quest. This method never produces an offer."""
        if quest_id is not None and not decimal(quest_id):
            raise ValueError('Bounded decimal quest ID required')
        if enabled is not None and type(enabled) is not bool:
            raise ValueError('Explicit boolean quest selection required')
        if alive is not None and type(alive) is not bool:
            raise ValueError('Explicit alive observation required')
        chosen = not (self._enabled and self._selected == quest_id) if enabled is None else enabled
        if not chosen:
            return self.stop('user_stop')
        if quest_id is None:
            raise ValueError('Select a quest before enabling automation')
        supplied = context(owner_context) if owner_context is not None else self._context
        if supplied is None:
            raise ValueError('Observe the quest owner before selecting a quest')
        if self._context is not None and supplied != self._context:
            self.stop('stale_context')
            raise ValueError('Quest owner context changed')
        if self._unknown:
            raise RuntimeError('Unknown quest action outcome remains fenced')
        if alive is False or self._alive is False:
            return self.stop('death')
        # An in-flight request belongs to its original scope/quest. A new click
        # may stop it locally but cannot reinterpret or erase its receipt.
        if self._pending is not None:
            raise RuntimeError('Wait for the existing quest action outcome')
        if self._selected not in (None, quest_id):
            self._cancel_pending = True
        self._context = supplied
        self._selected, self._enabled = quest_id, True
        self._offer = None
        self._state, self._reason = 'waiting_data', 'not_admitted'
        return self.snapshot()

    def observe(self, snapshot):
        """Observe a bounded owner snapshot; no wall clock or external IO."""
        if type(snapshot) is not dict:
            raise ValueError('Quest owner snapshot required')
        character = snapshot.get('character')
        if snapshot.get('state') != 'connected' or type(character) is not dict:
            self._connected = False
            self._alive = None
            self.stop('connection_lost')
            return self.snapshot()
        try:
            current = context(dict(bot_id=snapshot.get('bot_id'), session_id=snapshot.get('session_id'),
                character_key=character.get('key'), world_id=character.get('world_id'),
                source_sha256=snapshot.get('source_sha256')))
        except ValueError:
            self.stop('stale_context')
            raise
        if self._context is not None and current != self._context:
            self.stop('stale_context')
            self._context = current
            self._connected = True
            self._alive = None
            return self.snapshot()
        self._context, self._connected = current, True
        coverage = snapshot.get('coverage')
        hp = character.get('hp')
        known_hp = type(coverage) is dict and coverage.get('vitals') in ('received', 'partial') and type(hp) is int and hp >= 0
        self._alive = hp > 0 if known_hp else None
        if known_hp and hp == 0:
            self.stop('death')
        self._offer = None
        queue = snapshot.get('action_queue', {})
        if type(queue) is not dict:
            queue = {}
        records = queue.get('records', [])
        if type(records) is not list or len(records) > 64:
            raise ValueError('Bounded action receipts required')
        if queue.get('blocked') is True:
            self.stop('unknown_result')
        if self._pending is not None:
            matches = [row for row in records if type(row) is dict and row.get('request_id') == self._pending['request_id']]
            if len(matches) > 1:
                self.stop('unknown_result')
            elif matches:
                status = matches[0].get('status')
                if status == 'unknown':
                    self.stop('unknown_result')
                elif status in ('confirmed', 'failed'):
                    self._pending = None
                    if status == 'failed' and self._enabled:
                        self._state, self._reason = 'blocked', 'waiting_data'
                        self._enabled = False
                        self._cancel_pending = True
        if self._unknown:
            self._state, self._reason = 'unknown', 'unknown_result'
            return self.snapshot()
        if not self._enabled:
            # Confirmed revival does not turn the preference back on.
            if self._state == 'dead' and known_hp and hp > 0:
                self._state = 'paused'
            return self.snapshot()
        if self._pending is not None or any(type(row) is dict and row.get('status') in ('queued', 'executing', 'sent') for row in records):
            self._state, self._reason = 'running', None
            return self.snapshot()
        self._state, self._reason = 'waiting_data', 'not_admitted'
        interaction = snapshot.get('interaction')
        if (type(interaction) is not dict or interaction.get('semantics') != 'owner_action_offers'
                or interaction.get('source_sha256') != current['source_sha256']
                or interaction.get('character_key') != current['character_key']
                or interaction.get('world_id') != current['world_id']
                or interaction.get('actions_ready') is not True):
            return self.snapshot()
        offers = interaction.get('actions')
        if type(offers) is not list or len(offers) > 48:
            raise ValueError('Bounded owner quest offers required')
        matched = [row for row in offers if type(row) is dict and row.get('kind') == 'quest_follow'
                   and row.get('arguments') == {'quest_id': self._selected}]
        if len(matched) != 1:
            return self.snapshot()
        offer = matched[0]
        if (offer.get('enabled') is not True or type(offer.get('context')) is not str
                or not _SHA.fullmatch(offer['context'])):
            return self.snapshot()
        signature = (self._selected, offer['context'])
        if signature in self._attempted:
            self._reason = 'waiting_data'
            return self.snapshot()
        self._offer = dict(kind='quest_follow', context=offer['context'], arguments={'quest_id': self._selected})
        self._state, self._reason = 'running', None
        return self.snapshot()

    def next_offer(self):
        """Read an admitted current offer. Caller must submit through its queue."""
        if (not self._enabled or not self._connected or self._alive is False or self._unknown
                or self._pending is not None or self._cancel_pending or self._offer is None):
            return None
        return copy.deepcopy(self._offer)

    def submitted(self, request_id, action_context):
        """Record the owner's accepted queue intent, not a transport/server success."""
        offer = self.next_offer()
        if (type(request_id) is not str or not _REQUEST.fullmatch(request_id)
                or offer is None or action_context != offer['context']):
            raise ValueError('Current admitted quest offer required')
        if len(self._attempted) >= 4096:
            self._state, self._reason = 'blocked', 'waiting_data'
            self._enabled = False
            raise BufferError('Quest automation attempt limit reached')
        self._attempted.add((self._selected, action_context))
        self._pending = dict(request_id=request_id, context=action_context)
        self._offer = None
        self._state, self._reason = 'running', None
        return self.snapshot()
