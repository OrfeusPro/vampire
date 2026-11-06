"""Local account console, owns at most two independent bot worker processes."""
import argparse
from http.client import HTTPException
import importlib.util
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import subprocess
import sys
import threading

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.account_store import AccountStore
from vampir_core.character_creation_plan import CLASS_CHOICES, random_nickname
from vampir_core.account_sdk_preparation import validate_sdk_preparation
from vampir_core.account_readiness import account_readiness
from vampir_core.bot_device_settings import connection_presets, new_identity
from vampir_core.device_templates import new_windows_device_name
from account_world import ID as WORLD_ID, WorldControl
from prototype_assets import PrototypeAssets

PROTOTYPE = HERE.parent / 'vampir/ui-prototype'
RESOURCES = Path('F:/PhoneExit Resources/Vampir')


class Jobs:
    def __init__(self, store, *, world_busy=lambda identifier: False):
        self.store, self.lock, self.jobs = store, threading.RLock(), {}
        self.world_busy = world_busy
        self.verification = store.load_verification_checkpoint()
        if self.verification and self.verification['state'] in ('running', 'cancelling'):
            self.verification.update(state='stopped', failed=self.verification['active'], active=None,
                manual_retry=False, message='Панель перезапустилась во время проверки. Результат текущего аккаунта не подтверждён.')
            self._save_verification()

    def verification_snapshot(self):
        with self.lock:
            if self.verification is None:
                return None
            queue = self.verification
            return dict(state=queue['state'], active=queue['active'], pending=list(queue['pending']),
                        completed=list(queue['completed']), failed=queue['failed'],
                        manual_retry=queue.get('manual_retry', False), message=queue.get('message', ''))

    def _save_verification(self):
        self.store.save_verification_checkpoint(self.verification_snapshot())

    def _verification_profile(self, identifiers):
        accounts = {row['id']: row for row in self.store.accounts()}
        for identifier in identifiers:
            row = accounts.get(identifier)
            google = row and row.get('login_provider') == 'google'
            if (not row or not row['enabled'] or row.get('device_type') == 'Не использовать' or self.jobs.get(identifier, {}).get('running')
                    or self.world_busy(identifier)
                    or (google and row['socks_port'] is not None)
                    or (not google and (not row['mail_password_saved'] or not row['email'].endswith('@vampir.top')))):
                raise ValueError('Выберите свободные включённые аккаунты: Google с прямым выходом либо Netmarble с паролем почты @vampir.top.')
        spec = importlib.util.spec_from_file_location('account_verification_profile', HERE / 'verify-account.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.selected_profile()

    def is_reserved(self, identifier):
        queue = self.verification
        return bool(queue and queue['state'] in ('running', 'cancelling') and
                    (identifier == queue['active'] or identifier in queue['pending']))

    def verify_batch(self, identifiers):
        if (type(identifiers) is not list or not 1 <= len(identifiers) <= 32
                or any(type(identifier) is not str for identifier in identifiers)
                or len(set(identifiers)) != len(identifiers)):
            raise ValueError('Select 1–32 distinct accounts')
        with self.lock:
            if self.verification and self.verification['state'] in ('running', 'cancelling'):
                raise ValueError('Verification queue is already active')
            if self.verification and self.verification.get('manual_retry'):
                raise ValueError('Resume or stop the current queue first')
            selector = self._verification_profile(identifiers)
            self.verification = dict(state='running', active=None, pending=list(identifiers),
                                     completed=[], failed=None, selector=selector)
            self._next_verification()

    def resume_verification_manually(self):
        with self.lock:
            queue = self.verification
            if not queue or queue['state'] != 'stopped' or not queue.get('manual_retry') or not queue['failed']:
                raise ValueError('No verification account is waiting for manual sign-in')
            remaining = [queue['failed'], *queue['pending']]
            selector = self._verification_profile(remaining)
            queue.update(state='running', active=None, pending=remaining, failed=None, selector=selector)
            self._next_verification(manual_sign_in=True)

    def _next_verification(self, *, manual_sign_in=False):
        queue = self.verification
        if not queue['pending']:
            queue.update(state='completed', active=None, manual_retry=False, message='')
            self._save_verification()
            return
        identifier = queue['pending'].pop(0)
        queue.update(active=identifier, manual_retry=False, message='')
        self._save_verification()
        try:
            self.start(identifier, 'verify', _verification_profile=queue['selector'], manual_sign_in=manual_sign_in)
        except (ValueError, OSError, RuntimeError):
            queue.update(state='stopped', active=None, failed=identifier, manual_retry=manual_sign_in,
                         message='Не удалось запустить проверку. Проверьте состояние панели.')
            self._save_verification()
            raise

    def stop_verification(self, identifier=None):
        with self.lock:
            queue = self.verification
            if not queue:
                return
            if identifier is None and queue['state'] == 'stopped' and queue.get('manual_retry'):
                queue.update(state='cancelled', manual_retry=False, message='Очередь остановлена пользователем.')
                self._save_verification()
                return
            if queue['state'] != 'running':
                return
            if identifier is not None and queue['active'] != identifier:
                return
            queue['state'] = 'cancelling'
            self._save_verification()
            job = self.jobs.get(queue['active'])
        if job:
            self._terminate(job['process'])

    def snapshot(self):
        with self.lock:
            return {key: {k: v for k, v in job.items() if k != 'process'} for key, job in self.jobs.items()}

    def start(self, identifier, operation, *, accept_required_terms=False, manual_mail_code=False, manual_sign_in=False,
              terms_country=None, terms_locale=None, basic_terms_mode=None, _verification_profile=None):
        if type(manual_sign_in) is not bool or (manual_sign_in and operation not in ('servers', 'characters', 'start', 'create', 'prepare-sdk', 'verify')):
            raise ValueError('Manual sign-in is only available for login operations')
        if type(manual_mail_code) is not bool or (manual_mail_code and operation != 'register'):
            raise ValueError('Invalid mail-code mode')
        if operation not in ('servers', 'characters', 'start', 'register', 'create', 'prepare-sdk', 'verify'):
            raise ValueError('Unknown operation')
        if (operation == 'verify') != (_verification_profile is not None):
            raise ValueError('Verification requires an explicit queue')
        with self.lock:
            account = next((a for a in self.store.accounts() if a['id'] == identifier), None)
            if account is None:
                raise ValueError('Unknown account')
            if self.world_busy(identifier):
                raise ValueError('Сначала выйдите из мира выбранным персонажем')
            if account.get('device_type') == 'Не использовать':
                raise ValueError('Аккаунт отмечен «Не использовать». Сначала измените его режим в настройках.')
            if account.get('login_provider', 'email') == 'google':
                if operation != 'verify':
                    raise ValueError('Для Google пока доступна верификация с ручным входом и кодом.')
                if account['socks_port'] is not None:
                    raise ValueError('Ручной вход Google поддерживает прямой выход ПК.')
                manual_sign_in = True
            if not account.get('enabled', True):
                raise ValueError('This account is disabled')
            if operation == 'prepare-sdk':
                validate_sdk_preparation(account, country=terms_country, locale=terms_locale, mode=basic_terms_mode)
            elif any(value is not None for value in (terms_country, terms_locale, basic_terms_mode)):
                raise ValueError('Terms query is only available for SDK preparation')
            if operation == 'create' and (account['create_class'] != 'Gunner' or account['server_id'] is None
                    or account['character_index'] is not None or account['character_key'] is not None):
                raise ValueError('Сначала сохраните сервер и класс Carnage без назначенного персонажа.')
            if operation == 'register' and (accept_required_terms is not True or (not manual_mail_code and not account['mail_password_saved'])
                    or account['registration_status'] in ('registered', 'in_progress', 'email_in_use', 'nid_verified', 'sdk_created')):
                raise ValueError('Registration requires a mailbox password and explicit terms acceptance')
            if operation != 'verify' and self.is_reserved(identifier):
                raise ValueError('Account is in the verification queue')
            if self.jobs.get(identifier, {}).get('running'):
                raise ValueError('This account already has a job')
            if sum(bool(job.get('running')) for job in self.jobs.values()) >= 2:
                raise ValueError('At most two workers may run')
            command = [sys.executable, '-X', 'utf8', str(HERE / 'account-worker.py'),
                '--store', str(self.store.path.resolve()), '--account', identifier, '--operation', operation]
            if operation == 'register':
                command.append('--accept-required-terms')
            if manual_mail_code:
                command.append('--manual-mail-code')
            if manual_sign_in:
                command.append('--manual-sign-in')
            if operation == 'prepare-sdk':
                command.extend(['--terms-country', terms_country, '--terms-locale', terms_locale,
                                '--basic-terms-mode', basic_terms_mode])
            if operation == 'verify':
                command.extend(['--verification-profile', _verification_profile])
            process = subprocess.Popen(command,
                stdin=subprocess.PIPE if manual_mail_code else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            job = dict(process=process, running=True, active=False, status='connecting',
                stage='starting', message='Подготовка подключения.', characters=[],
                region=account['region'], server_id=account['server_id'], account_id=identifier, operation=operation,
                device_fingerprint=self.store._fingerprint(account),
                device_template_id=account.get('device_template_id'), device_template_revision=account.get('device_template_revision'),
                manual_mail_code=manual_mail_code, manual_sign_in=manual_sign_in, code_sent=False)
            self.jobs[identifier] = job
            threading.Thread(target=self._watch, args=(job,), daemon=True).start()

    def _watch(self, job):
        process = job['process']
        try:
            for _ in range(2048):
                line = process.stdout.readline(65537)
                if not line:
                    break
                if len(line) > 65536:
                    raise ValueError('Worker output exceeds budget')
                event = json.loads(line)
                with self.lock:
                    if event.get('event') == 'phase':
                        job['stage'] = str(event.get('stage', 'unknown'))[:100]
                    elif event.get('event') == 'registration':
                        job['registration'] = {key: event.get(key) for key in
                            ('path', 'mail_sent', 'code_submitted', 'password_submitted', 'complete')}
                    elif event.get('event') == 'active':
                        job.update(active=True, status='active', message=event['message'])
                    elif event.get('event') == 'result':
                        job.update(active=False, status=event['status'], message=event['message'],
                            characters=event.get('characters', []), login_code=event.get('login_code'),
                            sdk_error=event.get('sdk_error'))
                        if job['operation'] == 'verify':
                            job.update(verification_status=event.get('verification_status'),
                                       verification_steps=event.get('verification_steps', []),
                                       manual_sign_in_available=event.get('manual_sign_in_available') is True)
            process.wait(timeout=10)
        except Exception:
            self._terminate(process)
            with self.lock:
                job.update(status='error', message='Рабочий процесс завершился с ошибкой.')
        finally:
            process.stdout.close()
            if process.stdin:
                process.stdin.close()
            if job['operation'] == 'register':
                account = next(a for a in self.store.accounts() if a['id'] == job['account_id'])
                if account['registration_status'] == 'in_progress':
                    self.store.registration_status(job['account_id'], 'unconfirmed')
            if job['operation'] == 'create':
                for attempt in self.store.creation_attempts():
                    if attempt['account_id'] == job['account_id'] and attempt['state'] == 'pending':
                        self.store.finish_creation(attempt['attempt_id'], state='unknown')
            with self.lock:
                job.update(running=False, active=False)
                if job['status'] in ('active', 'connecting'):
                    job.update(status='stopped', message='Процесс остановлен, соединение закрыто.')
                if job['operation'] == 'verify':
                    self._finish_verification(job)

    def _finish_verification(self, job):
        queue = self.verification
        identifier = job['account_id']
        if queue['state'] == 'cancelling':
            queue.update(state='cancelled', active=None, failed=identifier, manual_retry=False)
            job.update(status='stopped', message='Очередь остановлена пользователем.')
            self._save_verification()
            return
        if job['status'] != 'verified' or job['process'].returncode != 0:
            queue.update(state='stopped', active=None, failed=identifier, message=job['message'],
                         manual_retry=job.get('manual_sign_in_available', False))
            self._save_verification()
            return
        self.store.record_device_verification(identifier, job['device_fingerprint'])
        queue['completed'].append(identifier)
        try:
            self._next_verification()
        except (ValueError, OSError, RuntimeError):
            pass  # _next_verification records the failed launch in the queue snapshot.

    @staticmethod
    def _terminate(process):
        if process.poll() is not None:
            return
        if sys.platform == 'win32':
            subprocess.run(['taskkill.exe', '/PID', str(process.pid), '/T', '/F'],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    def submit_code(self, identifier, code):
        if type(code) is not str or len(code) != 5 or not code.isascii() or not code.isdigit():
            raise ValueError('Expected five-digit code')
        with self.lock:
            job = self.jobs.get(identifier)
            if (not job or not job['running'] or not job.get('manual_mail_code') or job['code_sent']
                    or job['stage'] != 'registration_code' or job['process'].poll() is not None):
                raise ValueError('No verification code is expected')
            job['process'].stdin.write((code + '\n').encode('ascii'))
            job['process'].stdin.flush()
            job['code_sent'] = True

    def stop(self, identifier):
        with self.lock:
            job = self.jobs.get(identifier)
            verify = bool(job and job['operation'] == 'verify' and job['running'])
            process = job.get('process') if job else None
        if verify:
            self.stop_verification(identifier)
            return
        if process:
            self._terminate(process)
        with self.lock:
            if job:
                job.update(running=False, active=False, status='stopped', message='Остановлено пользователем.')

    def close(self):
        if self.verification and self.verification['state'] == 'running':
            self.stop_verification()
        for identifier in list(self.jobs):
            self.stop(identifier)


def server(store, *, port=17949, world=None):
    world = world if world is not None else WorldControl(store)
    jobs, token = Jobs(store, world_busy=world.busy), secrets.token_urlsafe(32)
    # One server generation owns matching UI/API versions until its next launch.
    assets = {}
    for route, directory, filename, mime in (
        ('/', HERE / 'console', 'index.html', 'text/html'),
        ('/console.js', HERE / 'console', 'console.js', 'text/javascript'),
        ('/console.css', HERE / 'console', 'console.css', 'text/css'),
        ('/local-map-projection.js', PROTOTYPE, 'local-map-projection.js', 'text/javascript'),
        ('/prototype-live-model.js', PROTOTYPE, 'prototype-live-model.js', 'text/javascript'),
    ):
        data = (directory / filename).read_bytes()
        if mime == 'text/html':
            data = data.replace(b'__CONSOLE_TOKEN__', token.encode('ascii'))
        assets[route] = data, mime + '; charset=utf-8'
    try:
        prototype = PrototypeAssets(RESOURCES, token)
    except (OSError, ValueError):
        prototype = None
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def setup(self):
            self.request.settimeout(5)
            super().setup()

        def response(self, status, value, mime='application/json; charset=utf-8'):
            data = value if type(value) is bytes else json.dumps(value, ensure_ascii=False).encode('utf-8')
            self.send_response(status)
            for name, content in (('Content-Type', mime), ('Content-Length', str(len(data))),
                ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'),
                ('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors "
                    + ("'self'" if self.path.startswith('/prototype/') else "'none'") + "; base-uri 'none'")):
                self.send_header(name, content)
            self.end_headers()
            self.wfile.write(data)

        def trusted(self, api=False):
            origin = 'http://127.0.0.1:' + str(self.server.server_port)
            if self.headers.get('Host') != origin[7:] or self.headers.get('Origin') not in (None, origin):
                return False
            return not api or secrets.compare_digest(self.headers.get('X-Console-Token', ''), token)

        def do_GET(self):
            if not self.trusted():
                return self.response(403, dict(error='Forbidden'))
            route = self.path.partition('?')[0]
            if route == '/world-map':
                self.send_response(302)
                self.send_header('Location', '/prototype/index.html?mode=group' + ('&' + self.path.partition('?')[2] if '?' in self.path else ''))
                self.end_headers()
                return
            if route.startswith('/prototype/'):
                try:
                    content = prototype.get(route) if prototype else None
                    return self.response(200, *content) if content else self.response(404, dict(error='Ресурс не найден'))
                except (OSError, ValueError):
                    return self.response(503, dict(error='Ресурсы прототипа недоступны'))
            if route in assets:
                return self.response(200, *assets[route])
            if self.path == '/api/world' and self.trusted(True):
                try:
                    return self.response(200, dict(sessions=world.snapshot()))
                except (ValueError, OSError):
                    return self.response(503, dict(error='Состояние игровых сессий недоступно'))
            if self.path != '/api/state' or not self.trusted(True):
                return self.response(403, dict(error='Forbidden'))
            accounts, catalogs, lists = store.accounts(), store.catalogs(), store.character_lists()
            return self.response(200, dict(accounts=accounts, jobs=jobs.snapshot(), catalogs=catalogs,
                verification=jobs.verification_snapshot(),
                character_lists=lists,
                readiness={a['id']: account_readiness(a, catalogs, lists) for a in accounts},
                connection_presets=connection_presets()[:1] + store.connection_presets(),
                device_templates=store.device_templates(),
                character_connections=store.character_connections(),
                creation_attempts=store.creation_attempts(),
                creation_classes=[dict(key=key, label=label) for key, label in CLASS_CHOICES],
                device_profiles=[dict(id='current-pc', name='Текущий ПК', available=True),
                                 dict(id='custom', name='Отдельный профиль бота', available=True)]))

        def do_POST(self):
            if not self.trusted(True):
                return self.response(403, dict(error='Forbidden'))
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 1 <= size <= 16384 or self.headers.get('Content-Type') != 'application/json':
                    raise ValueError('Invalid request')
                body = json.loads(self.rfile.read(size))
                if type(body) is not dict:
                    raise ValueError('Invalid request')
                if self.path == '/api/world':
                    identifier, action = body.get('id'), body.get('action')
                    if not isinstance(identifier, str) or not WORLD_ID.fullmatch(identifier):
                        raise ValueError('Invalid account')
                    if action == 'start' and set(body) == {'id', 'action'}:
                        with jobs.lock:
                            if jobs.jobs.get(identifier, {}).get('running') or jobs.is_reserved(identifier):
                                raise ValueError('Аккаунт занят другой операцией')
                            world.start(identifier)
                    elif action == 'stop' and set(body) == {'id', 'action', 'session_id'}:
                        world.stop(identifier, body['session_id'])
                    elif action in ('actions', 'policy', 'quest-automation') and set(body) == {'id', 'action', 'session_id', 'payload'}:
                        return self.response(202, world.command(identifier, body['session_id'], action, body['payload']))
                    else:
                        raise ValueError('Invalid world action')
                    return self.response(202, dict(ok=True))
                if self.path == '/api/save':
                    with jobs.lock:
                        existing = next((a for a in store.accounts() if a['email'] == body['email'].strip().lower()), None)
                        if existing and (jobs.jobs.get(existing['id'], {}).get('running') or jobs.is_reserved(existing['id']) or world.busy(existing['id'])):
                            raise ValueError('Stop this bot before editing')
                        identifier = store.save(body['email'], password=body.get('password') or None,
                            mail_password=body.get('mail_password') or None, assignment=body['assignment'])
                    return self.response(200, dict(id=identifier))
                if self.path == '/api/nickname':
                    return self.response(200, dict(nickname=random_nickname(a.get('create_nickname', '') for a in store.accounts())))
                if self.path == '/api/device-identity':
                    return self.response(200, dict(identity=new_identity(),
                        device_name=new_windows_device_name({t['device_name'] for t in store.device_templates()})))
                if self.path == '/api/current-pc':
                    if body:
                        raise ValueError('Current PC observation does not accept settings')
                    spec = importlib.util.spec_from_file_location('console_current_pc', HERE / 'current-pc.py')
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    return self.response(200, module.observation())
                if self.path == '/api/device-template':
                    with jobs.lock:
                        identifier = body.get('id')
                        members = next((t['members'] for t in store.device_templates() if t['id'] == identifier), [])
                        if any(jobs.jobs.get(a['id'], {}).get('running') or jobs.is_reserved(a['id']) for a in members):
                            raise ValueError('Сначала завершите работу аккаунтов этого устройства.')
                        identifier = store.save_device_template(identifier=identifier, name=body['name'],
                            device_name=body['device_name'], settings=body['settings'], expected_revision=body.get('revision'))
                    return self.response(200, dict(id=identifier))
                if self.path == '/api/assign-device':
                    with jobs.lock:
                        if jobs.jobs.get(body['account_id'], {}).get('running') or jobs.is_reserved(body['account_id']):
                            raise ValueError('Сначала завершите работу этого аккаунта.')
                        store.assign_device_template(body['account_id'], body.get('template_id'))
                    return self.response(200, dict(ok=True))
                if self.path == '/api/generate-devices':
                    with jobs.lock:
                        if any(job.get('running') for job in jobs.jobs.values()) or jobs.verification_snapshot().get('state') in ('running', 'cancelling'):
                            raise ValueError('Генерация доступна после завершения работающих сессий.')
                        spec = importlib.util.spec_from_file_location('console_device_baseline', HERE / 'current-pc.py')
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        result = store.generate_device_templates(module.observation()['device_settings'])
                    return self.response(200, result)
                if self.path == '/api/connection-preset':
                    return self.response(200, dict(id=store.save_connection_preset(body['name'], body['settings'])))
                if self.path == '/api/reveal':
                    return self.response(200, dict(password=store.reveal_password(body['id'], body['kind'])))
                if self.path == '/api/job':
                    if body['operation'] == 'stop':
                        jobs.stop(body['id'])
                    else:
                        jobs.start(body['id'], body['operation'], accept_required_terms=body.get('accept_required_terms', False),
                            manual_mail_code=body.get('manual_mail_code', False), manual_sign_in=body.get('manual_sign_in', False),
                            terms_country=body.get('terms_country'), terms_locale=body.get('terms_locale'),
                            basic_terms_mode=body.get('basic_terms_mode'))
                    return self.response(200, dict(ok=True))
                if self.path == '/api/registration-code':
                    jobs.submit_code(body['id'], body['code'])
                    return self.response(200, dict(ok=True))
                if self.path == '/api/verification-queue':
                    if body == {'action': 'stop'}:
                        jobs.stop_verification()
                    elif body == {'action': 'resume-manual'}:
                        jobs.resume_verification_manually()
                    elif set(body) == {'accounts'}:
                        jobs.verify_batch(body['accounts'])
                    else:
                        raise ValueError('Invalid verification action')
                    return self.response(200, dict(ok=True))
                return self.response(404, dict(error='Unknown action'))
            except (ValueError, KeyError, TypeError, RuntimeError, OSError, HTTPException):
                return self.response(400, dict(error='Проверьте данные, пароль и состояние бота. Перед изменением остановите его.'))
    http = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    http.daemon_threads = True
    return http, jobs


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--store', type=Path, default=HERE / '.local/console.sqlite3')
    parser.add_argument('--port', type=int, default=17949)
    args = parser.parse_args()
    http, jobs = server(AccountStore(args.store), port=args.port)
    print(json.dumps(dict(console='http://127.0.0.1:' + str(http.server_port))), flush=True)
    try:
        http.serve_forever(poll_interval=.2)
    except KeyboardInterrupt:
        pass
    finally:
        jobs.close()
        http.server_close()
