"""One explicitly admitted server test for a Time step of quest 110110."""
import time

from .bounded_world_admission import SOURCE, time_probe_chain, time_probe_index
from .quest_update import QuestUpdate

QUEST_ID = 110110
WORLD_ID = 10010
TIME_SECONDS = .1
POSITION_SOURCE = 'world_move_finish_result'
PENDING = ('queued', 'socket_accepted')


class QuestTimeProbe:
    def __init__(self, *, source_sha256):
        self._task_index = time_probe_index(source_sha256)
        self._chain = time_probe_chain(source_sha256)
        self._first_reply = None
        self._first_quest_context = None
        self.state = 'waiting_snapshot'
        self.result = None
        self._connection = self._ticket = self._scope = None
        self._ready_at = self._deadline = None

    def snapshot(self):
        result = dict(quest_id=str(QUEST_ID), task_index=self._task_index, state=self.state,
                      position_source=POSITION_SOURCE, actor_vector_verified=False,
                      quest_completed=False, result=self.result.copy() if self.result else None)
        if self._chain:
            result['first_reply'] = self._first_reply.copy() if self._first_reply else None
        return result

    def tick(self, snapshot, connection, *, now):
        if self.state not in ('waiting_snapshot', 'waiting_next_step', *PENDING):
            return
        person = snapshot.get('character') or {}
        scope = person.get('key'), person.get('world_id')
        if self._scope is not None and (scope != self._scope or connection is not self._connection):
            self.state = 'outcome_unknown' if self._ticket is not None else 'scope_changed'
            return
        if not connection.active or person.get('hp') == 0:
            self.state = 'outcome_unknown' if self._ticket is not None else 'unavailable'
            return
        if self.state in PENDING:
            if now >= self._deadline:
                self.state = 'outcome_unknown'
            else:
                self.state = self._transport_state()
            return

        world = connection.world_entry
        position = world.target_position if world else None
        if (snapshot.get('state') != 'connected' or world is None or world.source_sha256 != SOURCE
                or not world.complete_world or world.finish_result_code != 0 or world.state != 'finish_response'
                or position is None or position.source != POSITION_SOURCE or position.world_id != WORLD_ID
                or scope[1] != WORLD_ID or not scope[0]):
            return
        if self._ready_at is None:
            self._connection, self._scope, self._ready_at = connection, scope, now
        if now - self._ready_at > 30:
            self.state = 'stale_snapshot'
            return
        if type(person.get('hp')) is not int or person['hp'] <= 0:
            return
        context = snapshot.get('quest_snapshot') or {}
        if (snapshot.get('coverage', {}).get('quests') != 'last_received_message'
                or (context.get('character_key'), context.get('world_id')) != scope
                or context.get('source_sha256') != SOURCE or context.get('packet_id') != 1854):
            return
        rows = [row for row in snapshot.get('quests', ()) if row.get('id') == str(QUEST_ID)]
        if len(rows) != 1:
            return
        index = rows[0]['progress']['raw08']
        # The retained first QuestSync is expected to lag its own 1811. A
        # replacement QuestSync must agree with the next step before sending.
        previous_snapshot = (self.state == 'waiting_next_step' and index == 0
                             and context is self._first_quest_context)
        if rows[0]['state'] != 2 or (index != self._task_index and not previous_snapshot):
            self.state = 'ineligible_step'
            return
        if (now - self._ready_at < TIME_SECONDS
                or not 0 <= time.time_ns() // 1000000 - context['received_at_ms'] <= 30000):
            return
        try:
            payload = QuestUpdate(position.vector.finite_values(), 0, QUEST_ID, self._task_index)
            self._ticket = connection.queue_tracked_quest_update(payload, source_sha256=SOURCE)
        except (ValueError, RuntimeError, BufferError):
            self.state = 'not_queued'
            return
        if self._chain and self._task_index == 0:
            self._first_quest_context = context
        self.state, self._deadline = 'queued', now + 15

    def _transport_state(self):
        transport = self._connection.quest_send_status(self._ticket)
        return transport if transport in PENDING else 'outcome_unknown'

    def receive(self, result, *, character_key, world_id, now):
        if self.state not in PENDING:
            return False
        if now >= self._deadline:
            self.state = 'outcome_unknown'
            return False
        if self._scope != (str(character_key), world_id) or self._transport_state() != 'socket_accepted':
            return False
        if result is None:
            self.state = 'outcome_unknown'
            return False
        if result.quest_id != QUEST_ID:
            return False
        index = result.progress.raw08
        advanced = result.result_code == 0 and result.state == 2 and index == self._task_index + 1
        self.result = dict(packet_id=1811, result_code=result.result_code, state=result.state,
                           task_index=index, advanced=advanced)
        self.state = 'advanced' if advanced else 'rejected' if result.result_code else 'accepted_without_advance'
        self._connection.release_quest_send(self._ticket)
        self._ticket = None
        if self._chain and self._task_index == 0 and advanced:
            self._first_reply, self.result = self.result, None
            self._task_index = 1
            self._ready_at = now
            self.state = 'waiting_next_step'
        return True

    def close(self):
        if self.state in PENDING:
            self.state = 'outcome_unknown'
        elif self.state in ('waiting_snapshot', 'waiting_next_step'):
            self.state = 'cancelled'
