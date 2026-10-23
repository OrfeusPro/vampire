"""Local account console, owns at most two independent bot worker processes."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import subprocess
import sys
import threading

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.account_store import AccountStore
from vampir_core.character_creation_plan import CLASS_CHOICES, random_nickname
from vampir_core.account_sdk_preparation import validate_sdk_preparation
from vampir_core.account_readiness import account_readiness


class Jobs:
    def __init__(self, store):
        self.store, self.lock, self.jobs = store, threading.RLock(), {}

    def snapshot(self):
        with self.lock:
            return {key: {k: v for k, v in job.items() if k != 'process'} for key, job in self.jobs.items()}

    def start(self, identifier, operation, *, accept_required_terms=False, manual_mail_code=False, manual_sign_in=False,
              terms_country=None, terms_locale=None, basic_terms_mode=None):
        if type(manual_sign_in) is not bool or (manual_sign_in and operation not in ('servers', 'characters', 'start', 'create', 'prepare-sdk')):
            raise ValueError('Manual sign-in is only available for login operations')
        if type(manual_mail_code) is not bool or (manual_mail_code and operation != 'register'):
            raise ValueError('Invalid mail-code mode')
        if operation not in ('servers', 'characters', 'start', 'register', 'create', 'prepare-sdk'):
            raise ValueError('Unknown operation')
        account = next((a for a in self.store.accounts() if a['id'] == identifier), None)
        if account is None:
            raise ValueError('Unknown account')
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
        with self.lock:
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
            process = subprocess.Popen(command,
                stdin=subprocess.PIPE if manual_mail_code else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            job = dict(process=process, running=True, active=False, status='connecting',
                stage='starting', message='Подготовка подключения.', characters=[],
                region=account['region'], server_id=account['server_id'], account_id=identifier, operation=operation,
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
            process = job.get('process') if job else None
        if process:
            self._terminate(process)
        with self.lock:
            if job:
                job.update(running=False, active=False, status='stopped', message='Остановлено пользователем.')

    def close(self):
        for identifier in list(self.jobs):
            self.stop(identifier)


def server(store, *, port=17949):
    jobs, token = Jobs(store), secrets.token_urlsafe(32)
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
                ('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'")):
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
            if self.path in ('/', '/console.js', '/console.css'):
                filename = {'/': 'index.html', '/console.js': 'console.js', '/console.css': 'console.css'}[self.path]
                data = (HERE / 'console' / filename).read_bytes()
                if filename == 'index.html':
                    data = data.replace(b'__CONSOLE_TOKEN__', token.encode('ascii'))
                return self.response(200, data, {'/': 'text/html; charset=utf-8', '/console.js': 'text/javascript; charset=utf-8', '/console.css': 'text/css; charset=utf-8'}[self.path])
            if self.path != '/api/state' or not self.trusted(True):
                return self.response(403, dict(error='Forbidden'))
            accounts, catalogs, lists = store.accounts(), store.catalogs(), store.character_lists()
            return self.response(200, dict(accounts=accounts, jobs=jobs.snapshot(), catalogs=catalogs,
                character_lists=lists,
                readiness={a['id']: account_readiness(a, catalogs, lists) for a in accounts},
                creation_attempts=store.creation_attempts(),
                creation_classes=[dict(key=key, label=label) for key, label in CLASS_CHOICES],
                device_profiles=[dict(id='current-pc', name='Текущий ПК · общие данные устройства', available=True)]))

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
                if self.path == '/api/save':
                    existing = next((a for a in store.accounts() if a['email'] == body['email'].strip().lower()), None)
                    if existing and jobs.snapshot().get(existing['id'], {}).get('running'):
                        raise ValueError('Stop this bot before editing')
                    identifier = store.save(body['email'], password=body.get('password') or None,
                        mail_password=body.get('mail_password') or None, assignment=body['assignment'])
                    return self.response(200, dict(id=identifier))
                if self.path == '/api/nickname':
                    return self.response(200, dict(nickname=random_nickname(a.get('create_nickname', '') for a in store.accounts())))
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
                return self.response(404, dict(error='Unknown action'))
            except (ValueError, KeyError, TypeError, RuntimeError):
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
