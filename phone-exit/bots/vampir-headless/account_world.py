"""Console adapter for isolated loopback world owners and explicit Start/Stop."""
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection, HTTPException
import hashlib
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
from threading import RLock, Thread
from time import monotonic
from uuid import uuid4

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent / 'resource-tools/vampir'
BUILTIN_PORTS = (17947, 17948, 17950)
ACTIVE = ('connecting', 'connected')
ID = re.compile(r'[a-zA-Z0-9_-]{1,48}')
SHA = re.compile(r'[0-9a-f]{64}')


def runtime_executable():
    """Use the retained spelling of the very same Python executable on Windows."""
    selector = json.loads((TOOLS / 'knowledge/entry-native-current.json').read_bytes())
    pointer = selector['proofs']['clock-world-current']
    raw = Path(pointer['path']).read_bytes()
    if not SHA.fullmatch(pointer['sha256']) or hashlib.sha256(raw).hexdigest()!=pointer['sha256']:
        raise ValueError('Изменилось доказательство среды входа')
    retained = json.loads(raw)['definition']['executable']
    if not isinstance(retained,str) or not Path(retained).is_file() or not Path(retained).samefile(sys.executable):
        raise ValueError('Python не соответствует проверенной среде входа')
    return retained


def owner_request(port, path, body=None, *, token=None):
    connection = HTTPConnection('127.0.0.1', port, timeout=1)
    try:
        headers = {'Content-Type': 'application/json', 'X-Session-Token': token} if token else {}
        connection.request('GET' if body is None else 'POST', path,
                           None if body is None else json.dumps(body), headers)
        with connection.getresponse() as response:
            raw = response.read(262145)
            if response.status != (200 if body is None else 202) or len(raw) > 262144:
                raise ValueError('Ответ владельца сессии недоступен')
            value = json.loads(raw)
            if type(value) is not dict:
                raise ValueError('Некорректный ответ владельца сессии')
            return value
    finally:
        connection.close()


def eligible(account):
    return bool(account.get('enabled') and account.get('device_type') != 'Не использовать'
                and account.get('password_saved') and account.get('login_provider') != 'google'
                and account.get('auth_flow') == 'launcher' and account.get('server_id') is not None
                and account.get('character_index') is not None and account.get('character_key'))


def read_owner(port, identifiers):
    try:
        sessions = owner_request(port, '/sessions').get('sessions')
        if type(sessions) is not list or len(sessions) > 50:
            return None
    except (OSError, HTTPException, ValueError):
        return None
    rows = []
    for row in sessions:
        if type(row) is not dict:
            continue
        bot, session, state = (row.get(key) for key in ('bot_id', 'session_id', 'state'))
        if not isinstance(bot, str) or bot not in identifiers or not ID.fullmatch(bot) \
                or not isinstance(session, str) or not ID.fullmatch(session) or state not in (*ACTIVE, 'disconnected'):
            continue
        detail = {}
        try:
            detail = owner_request(port, f'/bots/{bot}/state')
        except (OSError, HTTPException, ValueError):
            pass
        if (detail.get('schema') != 2 or detail.get('bot_id') != bot or detail.get('session_id') != session
                or detail.get('state') not in (*ACTIVE, 'disconnected')):
            detail = {}
        rows.append(dict(port=port, bot_id=bot, session_id=session, state=detail.get('state', state),
            **{key: detail.get(key) for key in ('schema', 'mode', 'character', 'position', 'heartbeat', 'coverage', 'quests',
                'quest_snapshot', 'quest_update_result', 'tutorial', 'entities', 'environment', 'analysis', 'journal', 'error',
                'source_sha256', 'interaction', 'action_policy', 'action_queue')}))
    return rows


class WorldControl:
    def __init__(self, store):
        self.store = store
        self.directory = store.path.with_name(store.path.name + '.world')
        self.registry = self.directory / 'owners.json'
        self.lock = RLock()
        self.pending = set()
        self.errors = {}
        self.launches = {}
        self.cached = {}
        self.checked_at = float('-inf')

    def owners(self):
        if not self.registry.is_file():
            return {}
        with self.registry.open('rb') as stream:
            rows = json.loads(stream.read(16385))
        if (type(rows) is not dict or len(rows) > 128 or any(not ID.fullmatch(key)
                or type(value) is not int or not 49152 <= value <= 65535 for key, value in rows.items())
                or len(set(rows.values())) != len(rows)):
            raise ValueError('Повреждён список владельцев панели')
        return rows

    def snapshot(self, *, fresh=False):
        with self.lock:
            if not fresh and monotonic() - self.checked_at < 1:
                return self.cached
            accounts = {row['id']: row for row in self.store.accounts()}
            catalogs = self.store.catalogs()
            owners = self.owners()
            ports = list(dict.fromkeys((*BUILTIN_PORTS, *owners.values())))
            with ThreadPoolExecutor(max_workers=min(12, len(ports))) as pool:
                results = dict(zip(ports, pool.map(lambda port: read_owner(port, accounts), ports)))
            by_account = {identifier: [] for identifier in accounts}
            for rows in results.values():
                for row in rows or ():
                    by_account[row['bot_id']].append(row)
            builtins_available = all(results[port] is not None or not self.port_bound(port) for port in BUILTIN_PORTS)
            state = {}
            for identifier, account in accounts.items():
                rows = by_account[identifier]
                active = [row for row in rows if row['state'] in ACTIVE]
                # A retained active owner that timed out must never allow a second login.
                old = self.cached.get(identifier, {})
                unreachable = (old.get('port') is not None and old.get('state') in (*ACTIVE, 'unreachable')
                               and results.get(old['port']) is None)
                if len(active) > 1:
                    row = dict(state='conflict')
                elif active:
                    row = active[0]
                    self.errors.pop(identifier, None)
                elif identifier in self.pending:
                    row = dict(state='connecting', launch=self.launches.get(identifier))
                elif unreachable and self.port_bound(old['port']):
                    row = dict(state='unreachable', port=old['port'])
                elif identifier in owners and results[owners[identifier]] is None and self.port_bound(owners[identifier]):
                    row = dict(state='unreachable', port=owners[identifier])
                else:
                    row = next((row for row in rows if row.get('error')), dict(state='disconnected'))
                    row = dict(row, **self.terminal(identifier))
                    if identifier in self.errors:
                        row = dict(row, error=self.errors[identifier])
                server_id = account['server_id']
                servers = catalogs.get(account['region'], {}).get('servers', [])
                server = next((item['name'] for item in servers if item['id'] == server_id), None)
                state[identifier] = dict(row, region=account['region'], server_id=server_id, server=server,
                    can_start=eligible(account) and row['state'] == 'disconnected' and builtins_available)
            self.cached, self.checked_at = state, monotonic()
            return state

    def terminal(self, identifier):
        try:
            note_path = self.directory / (identifier + '.last-launch.json')
            with note_path.open('rb') as stream:
                note = json.loads(stream.read(2048))
            result_path = self.directory / note.get('output', '')
            if result_path.parent != self.directory or result_path.suffix != '.json':
                return {'error': note['error']} if isinstance(note.get('error'), str) else {}
            with result_path.open('rb') as stream:
                result = json.loads(stream.read(65536))
            row = next(row for row in result['sessions'] if row['account_id'] == identifier)
            if row.get('game_status') == 'session_stopped':
                return {}
            stage = row.get('stage')
            return {key: value for key, value in dict(error=stage or 'world_entry_not_completed',
                sdk_error_code=row.get('sdk_error_code'), login_result_code=row.get('login_result_code')).items()
                if value is not None and (type(value) is int or type(value) is str and ID.fullmatch(value))}
        except (OSError, ValueError, KeyError, TypeError, StopIteration):
            return {}

    @staticmethod
    def port_bound(port):
        with socket.socket() as probe:
            if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            try:
                probe.bind(('127.0.0.1', port))
            except OSError:
                return True
        return False

    def busy(self, identifier):
        return self.snapshot().get(identifier, {}).get('state') in (*ACTIVE, 'conflict', 'unreachable')

    def reserve_port(self, identifier):
        owners = self.owners()
        if identifier in owners and not self.port_bound(owners[identifier]):
            return owners[identifier]
        if len(owners) >= 128 and identifier not in owners:
            raise ValueError('Исчерпан список портов панели')
        for port in range(49152, 49408):
            if port not in owners.values() and not self.port_bound(port):
                owners[identifier] = port
                self.directory.mkdir(parents=True, exist_ok=True)
                temporary = self.directory / (uuid4().hex + '.tmp')
                try:
                    temporary.write_text(json.dumps(owners), encoding='utf-8')
                    temporary.replace(self.registry)
                finally:
                    temporary.unlink(missing_ok=True)
                return port
        raise ValueError('Нет свободного порта для владельца сессии')

    def start(self, identifier):
        with self.lock:
            rows = self.snapshot(fresh=True)
            if not rows.get(identifier, {}).get('can_start'):
                raise ValueError('Выберите свободный аккаунт с сохранённым персонажем')
            if sum(row['state'] == 'connecting' for row in rows.values()) >= 2:
                raise ValueError('Дождитесь завершения текущих подключений')
            port = self.reserve_port(identifier)
            self.pending.add(identifier)
            self.errors.pop(identifier, None)
            self.checked_at = float('-inf')
            Thread(target=self.launch, args=(identifier, port), daemon=True).start()

    def launch(self, identifier, port):
        stage = 'world_profile_prepare'
        try:
            def run(script, *args):
                child = subprocess.run([runtime_executable(), '-X', 'utf8', str(script), *args],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    encoding='utf-8', check=False, timeout=180,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
                if child.returncode:
                    if script.name == 'build-bounded-world-current.py':
                        (self.directory / (identifier + '.profile-error.log')).write_text(
                            child.stderr[-8192:], encoding='utf-8')
                    raise RuntimeError('Команда входа не завершилась')
                return json.loads(child.stdout)
            with self.lock:
                self.launches[identifier] = stage
            prepared = run(TOOLS / 'build-bounded-world-current.py')
            selector = prepared['selected_profile']
            if not selector.startswith('bounded-world:') or not SHA.fullmatch(selector[14:]):
                raise ValueError('Нет проверенного пакета входа')
            stage = 'world_owner_launch'
            with self.lock:
                self.launches[identifier] = stage
            output = self.directory / (identifier + '-' + uuid4().hex + '.json')
            (self.directory / (identifier + '.last-launch.json')).write_text(json.dumps(dict(
                stage=stage, output=output.name)), encoding='utf-8')
            result = run(HERE / 'run-bounded-world.py', '--account', identifier, '--profile', selector,
                         '--port', str(port), '--store', str(self.store.path.resolve()), '--output', str(output), '--detached')
            if result.get('status') not in ('ready', 'existing_owner') or result.get('port') != port:
                raise ValueError('Владелец не подтвердил запуск')
        except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
            with self.lock:
                code = stage + ('_timeout' if isinstance(error, subprocess.TimeoutExpired) else '_failed')
                self.errors[identifier] = code
                # Fixed stage/type only. Child stdout may contain private paths.
                self.directory.mkdir(parents=True, exist_ok=True)
                (self.directory / (identifier + '.last-launch.json')).write_text(json.dumps(dict(
                    stage=stage, error=code, error_type=type(error).__name__)), encoding='utf-8')
        finally:
            with self.lock:
                self.pending.discard(identifier)
                self.checked_at = float('-inf')

    def command(self, identifier, session_id, operation, payload):
        """Proxy only the current owner's scoped commands; tokens stay local."""
        if operation not in ('actions', 'policy', 'quest-automation') or type(payload) is not dict:
            raise ValueError('Недопустимое действие сессии')
        if set(payload) & {'bot_id', 'session_id'}:raise ValueError('Контекст сессии задаёт панель')
        with self.lock:
            row=self.snapshot(fresh=True).get(identifier,{})
            if row.get('state')!='connected' or row.get('session_id')!=session_id or not session_id:
                raise ValueError('Игровая сессия изменилась')
            path='/bots/'+identifier
            control=owner_request(row['port'],path+'/control')
            token=control.get('token')
            if (control.get('bot_id')!=identifier or control.get('session_id')!=session_id
                    or not isinstance(token,str) or not SHA.fullmatch(token)):
                raise ValueError('Владелец сессии изменился')
            result=owner_request(row['port'],path+'/'+operation,
                dict(payload,bot_id=identifier,session_id=session_id),token=token)
            if result.get('bot_id')!=identifier or result.get('session_id')!=session_id:
                raise ValueError('Ответ другой игровой сессии')
            self.checked_at=float('-inf')
            return result

    def stop(self, identifier, session_id):
        with self.lock:
            row = self.snapshot(fresh=True).get(identifier, {})
            if row.get('state') not in ACTIVE or row.get('session_id') != session_id or not session_id:
                raise ValueError('Игровая сессия изменилась')
            path = '/bots/' + identifier
            port = row['port']
            control = owner_request(port, path + '/control')
            token = control.get('token')
            if (control.get('bot_id') != identifier or control.get('session_id') != session_id
                    or not isinstance(token, str) or not SHA.fullmatch(token)):
                raise ValueError('Владелец сессии изменился')
            result = owner_request(port, path + '/stop', dict(bot_id=identifier, session_id=session_id), token=token)
            if result.get('state') != 'stopping':
                raise ValueError('Остановка не подтверждена')
            self.checked_at = float('-inf')
