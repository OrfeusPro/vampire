"""One explicit manual start; no retry, fabricated state or automatic task step."""
import copy
import math
import time
from .quest_start import SOURCE, encode_quest_start, decode_quest_start_result


class ManualQuestStart:
    def __init__(self, quest_id, *, source_sha256):
        from .bounded_world_admission import permits
        encode_quest_start(quest_id, source_sha256=source_sha256)
        if not permits(source_sha256, 'quest-start-manual-v1'):
            raise ValueError('Manual QuestStart requires its immutable admission')
        self.quest_id, self.source = quest_id, source_sha256
        self.state = 'waiting_snapshot'
        self.ticket = self.connection = self.scope = None
        self.deadline = None
        self.result = None
        self.decode_errors = self.unmatched = 0

    def snapshot(self):
        return dict(quest_id=str(self.quest_id), state=self.state, result=copy.deepcopy(self.result),
                    decode_errors=self.decode_errors, unmatched_results=self.unmatched,
                    automatic_task_execution=False)

    def tick(self, snapshot, connection, *, now):
        if type(now) not in (int, float) or not math.isfinite(now):
            raise ValueError('Explicit finite QuestStart clock required')
        if self.state not in ('waiting_snapshot', 'queued', 'socket_accepted'):
            return
        person = snapshot.get('character') or {}
        scope = (person.get('key'), person.get('world_id'))
        if self.scope is not None and scope != self.scope:
            self.state = 'scope_changed'
            return
        if not connection.active or person.get('hp') == 0:
            self.state = 'connection_lost' if not connection.active else 'character_dead'
            return
        if self.ticket is not None:
            if connection is not self.connection:
                raise ValueError('Manual QuestStart owner differs')
            transport = connection.quest_send_status(self.ticket)
            if transport == 'socket_accepted':
                self.state = 'socket_accepted'
            elif transport != 'queued':
                self.state = 'outcome_unknown'
                return
            if now >= self.deadline:
                self.state = 'outcome_unknown'
            return
        quest_context = snapshot.get('quest_snapshot') or {}
        if (snapshot.get('state') != 'connected' or snapshot.get('source_sha256', self.source) != self.source
                or snapshot.get('coverage', {}).get('quests') != 'last_received_message'
                or quest_context.get('source_sha256') != self.source
                or (quest_context.get('character_key'), quest_context.get('world_id')) != scope
                or not scope[0] or not scope[1] or type(person.get('hp')) is not int or person['hp'] <= 0):
            return
        rows = [row for row in snapshot.get('quests', []) if row.get('id') == str(self.quest_id)]
        if len(rows) != 1:
            return
        if rows[0]['state'] not in (1, 3):
            self.state = 'already_started' if rows[0]['state'] == 2 else 'ineligible_state'
            return
        age = time.time_ns() // 1000000 - quest_context.get('received_at_ms', 0)
        if not 0 <= age <= 30000:
            self.state = 'stale_snapshot'
            return
        # This is an explicit user-selected command, not a reconstructed UI
        # auto-start decision. The server evaluates remaining prerequisites.
        self.scope, self.connection = scope, connection
        try:
            self.ticket = connection.queue_tracked_quest_start(self.quest_id, source_sha256=self.source)
        except (ValueError, RuntimeError, BufferError):
            self.state = 'not_queued'
            return
        self.state, self.deadline = 'queued', now + 15

    def receive(self, body, *, character_key, world_id):
        if self.state not in ('queued', 'socket_accepted') or self.ticket is None:
            return False
        if time.monotonic() >= self.deadline:
            self.state = 'outcome_unknown'
            return False
        if self.scope != (str(character_key), world_id):
            self.unmatched += 1
            return False
        if self.connection.quest_send_status(self.ticket) != 'socket_accepted':
            self.unmatched += 1
            return False
        try:
            result = decode_quest_start_result(body, source_sha256=self.source)
        except (ValueError, BufferError):
            self.decode_errors += 1
            self.state = 'outcome_unknown'
            return False
        if result.quest_id != self.quest_id:
            self.unmatched += 1
            return False
        rows = [row for group in result.data.groups for row in group.quests if row.raw08 == self.quest_id]
        self.result = dict(packet_id=1804, result_code=result.result_code,
            quest_id=str(result.quest_id), matched_rows=len(rows),
            state=rows[0].raw10 if len(rows) == 1 else None,
            progress_index=rows[0].progress.raw08 if len(rows) == 1 else None,
            server_accepted=result.result_code == 0,
            started=result.result_code == 0 and len(rows) == 1 and rows[0].raw10 == 2,
            quest_completed=False)
        self.state = ('started' if self.result['started'] else
                      'accepted_without_state' if result.result_code == 0 else 'rejected')
        return True

    def close(self):
        if self.state in ('queued', 'socket_accepted'):
            self.state = 'outcome_unknown'
        elif self.state == 'waiting_snapshot':
            self.state = 'cancelled'
