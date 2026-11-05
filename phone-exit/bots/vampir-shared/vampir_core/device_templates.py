"""Persistent shared Windows devices, with two reserved account/character slots."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import secrets
import string
import uuid

from .bot_device_settings import validate, new_identity, metadata_values


def device_text(value, limit, label):
    if type(value) is not str or not value.strip() or len(value.strip()) > limit or any(ord(c) < 32 for c in value):
        raise ValueError(label)
    return value.strip()


def new_windows_device_name(used=()):
    """Generate the familiar desktop OOBE naming shape, without changing Windows."""
    for _ in range(100):
        name = 'DESKTOP-' + ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(7))
        if name not in used:
            return name
    raise RuntimeError('Не удалось создать свободное имя устройства.')


class DeviceTemplates:
    def _init_device_templates(self, db):
        db.execute('''CREATE TABLE IF NOT EXISTS device_templates(
            id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,device_name TEXT NOT NULL,
            settings TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1,source TEXT NOT NULL)''')
        db.execute('''CREATE TABLE IF NOT EXISTS device_verifications(
            account_id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,observed_utc TEXT NOT NULL)''')

    def _template_map(self, db=None):
        if db is None:
            with self._db() as opened:
                return self._template_map(opened)
        return {identifier: dict(id=identifier, name=name, device_name=device_name, settings=json.loads(settings),
                    revision=revision, source=source)
                for identifier, name, device_name, settings, revision, source in db.execute(
                    'SELECT id,name,device_name,settings,revision,source FROM device_templates ORDER BY rowid')}

    def _resolve_template(self, assignment, templates):
        assignment = deepcopy(assignment)
        identifier = assignment.get('device_template_id')
        if identifier:
            template = templates.get(identifier)
            if template is None:
                raise ValueError('Назначенный шаблон устройства отсутствует.')
            assignment.update(device_profile='custom', device_settings=validate(template['settings']),
                              device_name=template['device_name'])
        return assignment

    @staticmethod
    def _fingerprint(assignment):
        data = {k: assignment.get(k) for k in ('device_profile', 'device_settings', 'device_name', 'socks_port')}
        return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=True).encode()).hexdigest()

    def _check_template_capacity(self, db, identifier, account):
        if identifier is None:
            return
        if identifier not in self._template_map(db):
            raise ValueError('Шаблон устройства не найден.')
        count = sum(key != account and json.loads(raw).get('device_template_id') == identifier
                    for key, raw in db.execute('SELECT id,assignment FROM accounts'))
        if count >= 2:
            raise ValueError('В шаблоне уже заняты 2 места. Выберите другой шаблон.')

    def device_templates(self):
        with self._db() as db:
            templates = self._template_map(db)
            rows = db.execute('''SELECT a.id,a.email,a.assignment,r.character_name
                FROM accounts a LEFT JOIN active_game_roster r ON r.account_id=a.id ORDER BY a.rowid''').fetchall()
        for template in templates.values():
            template.update(capacity=2, members=[], display_metadata=metadata_values(template['settings']))
        for account, email, raw, name in rows:
            assignment = json.loads(raw)
            template = templates.get(assignment.get('device_template_id'))
            if template:
                template['members'].append(dict(id=account, email=email, character_name=name or '',
                    character_key=assignment.get('character_key'), server_id=assignment.get('server_id')))
        return list(templates.values())

    def save_device_template(self, *, name, device_name, settings, identifier=None, expected_revision=None):
        name = device_text(name, 100, 'Введите название шаблона, до 100 символов.')
        device_name = device_text(device_name, 20, 'Имя устройства: от 1 до 20 символов.')
        settings = validate(settings)
        if not settings.get('identity') or not settings.get('metadata', {}).get('I_DeviceModel'):
            raise ValueError('Укажите модель и все три постоянных ключа устройства.')
        if len(set(settings['identity'].values())) != 3:
            raise ValueError('Три ключа устройства должны различаться.')
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            templates = self._template_map(db)
            if identifier is not None and identifier not in templates:
                raise ValueError('Шаблон устройства не найден.')
            if identifier and expected_revision is not None and templates[identifier]['revision'] != expected_revision:
                raise ValueError('Шаблон уже изменён. Откройте актуальную версию перед редактированием.')
            for other in templates.values():
                if other['id'] != identifier and set(other['settings']['identity'].values()) & set(settings['identity'].values()):
                    raise ValueError('Ключи другого шаблона нельзя использовать для нового устройства.')
            if any(t['id'] != identifier and t['name'] == name for t in templates.values()):
                raise ValueError('Название шаблона уже занято.')
            if identifier is None:
                identifier = str(uuid.uuid4())
                db.execute('INSERT INTO device_templates VALUES(?,?,?,?,1,?)',
                    (identifier, name, device_name, json.dumps(settings), 'Создан в панели'))
            else:
                previous = templates[identifier]
                hardware_changed = (previous['device_name'] != device_name or previous['settings'] != settings)
                db.execute('UPDATE device_templates SET name=?,device_name=?,settings=?,revision=revision+1 WHERE id=?',
                    (name, device_name, json.dumps(settings), identifier))
                if hardware_changed:
                    db.execute("UPDATE accounts SET registration_status='nid_verified' WHERE registration_status='sdk_created' "
                               "AND json_extract(assignment,'$.device_template_id')=?", (identifier,))
        return identifier

    def assign_device_template(self, account, identifier):
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT assignment FROM accounts WHERE id=?', (account,)).fetchone()
            if row is None:
                raise ValueError('Аккаунт не найден.')
            self._check_template_capacity(db, identifier, account)
            assignment = self.assignment(json.loads(row[0]))
            previous = assignment.get('device_template_id')
            assignment['device_template_id'] = identifier
            db.execute('UPDATE accounts SET assignment=? WHERE id=?', (json.dumps(assignment), account))
            if previous != identifier:
                db.execute("UPDATE accounts SET registration_status='nid_verified' WHERE id=? AND registration_status='sdk_created'", (account,))

    def generate_device_templates(self, baseline):
        """Idempotently fill empty slots, then generate devices for unassigned accounts."""
        baseline = validate(baseline)
        baseline.pop('identity', None)
        if not baseline.get('cpu') or not baseline.get('windows'):
            raise ValueError('Для генерации нужны наблюдённые CPU и версия Windows.')
        model_generated = not baseline.get('metadata', {}).get('I_DeviceModel')
        baseline.setdefault('metadata', {}).setdefault('I_DeviceModel', 'Desktop PC')
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            templates = self._template_map(db)
            rows = db.execute('''SELECT a.id,a.assignment FROM accounts a
                LEFT JOIN active_game_roster r ON r.account_id=a.id
                ORDER BY r.account_id IS NULL,a.rowid''').fetchall()
            counts = {key: sum(json.loads(raw).get('device_template_id') == key for _, raw in rows) for key in templates}
            created, assigned = 0, 0
            sequence = 1
            for account, raw in rows:
                assignment = self.assignment(json.loads(raw))
                if assignment.get('device_template_id'):
                    continue
                free = next((key for key in templates if counts[key] < 2), None)
                if free is None:
                    used = {t['name'] for t in templates.values()} | {t['device_name'] for t in templates.values()}
                    while 'VAMPIR-PC-' + format(sequence, '02d') in used:
                        sequence += 1
                    name = 'VAMPIR-PC-' + format(sequence, '02d')
                    device_name = new_windows_device_name(used)
                    free = str(uuid.uuid4())
                    settings = deepcopy(baseline)
                    settings['identity'] = new_identity()
                    db.execute('INSERT INTO device_templates VALUES(?,?,?,?,1,?)',
                        (free, name, device_name, json.dumps(settings), 'На основе характеристик текущего ПК; отдельные ключи.' +
                         (' Модель Desktop PC задана шаблоном.' if model_generated else '')))
                    templates[free] = dict(id=free, name=name, device_name=device_name, settings=settings)
                    counts[free] = 0
                    created += 1
                assignment['device_template_id'] = free
                db.execute('UPDATE accounts SET assignment=? WHERE id=?', (json.dumps(assignment), account))
                db.execute("UPDATE accounts SET registration_status='nid_verified' WHERE id=? AND registration_status='sdk_created'", (account,))
                counts[free] += 1
                assigned += 1
        return dict(created=created, assigned=assigned, templates=len(templates))

    def record_device_verification(self, account, fingerprint):
        current = next((a for a in self.accounts() if a['id'] == account), None)
        if current is None or self._fingerprint(current) != fingerprint:
            return False
        with self._db() as db:
            db.execute('INSERT INTO device_verifications VALUES(?,?,?) ON CONFLICT(account_id) DO UPDATE SET '
                       'fingerprint=excluded.fingerprint,observed_utc=excluded.observed_utc',
                       (account, fingerprint, datetime.now(timezone.utc).isoformat()))
        return True
