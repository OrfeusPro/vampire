"""Deploy the storefront over verified FTPS. Credentials are stdin-only, never saved."""
import base64
import datetime
import ftplib
import getpass
import hashlib
import io
import json
import pathlib
import ssl
import sys

ROOT = pathlib.Path(__file__).resolve().parent
HOST = 'dd.rehost.com.ua'
USER = 'ftp@vampir.top'
WEBROOT = '/public_html'

def deploy():
    xmail_only = '--xmail-only' in sys.argv
    encoded = getpass.getpass('FTP credential input (base64): ')
    password = base64.b64decode(encoded, validate=True).decode('utf-8')
    ftp = ftplib.FTP_TLS(context=ssl.create_default_context(), timeout=40)
    ftp.connect(HOST, 21)
    ftp.login(USER, password)
    password = encoded = None
    ftp.prot_p()
    print('Verified FTPS connection established.', flush=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup = ROOT / 'var' / ('ftp-backup-' + stamp)
    backup.mkdir(parents=True)
    files = [(file, WEBROOT + '/' + file.relative_to(ROOT / 'dist').as_posix())
             for file in sorted((ROOT / 'dist').rglob('*')) if file.is_file()]
    if xmail_only:
        files = [(file, WEBROOT+'/xmail/'+file.name) for file in sorted((ROOT/'dist/xmail').glob('*')) if file.is_file()]
        files += [(ROOT/name,'/'+name) for name in ['xmail-imap.php','xmail-backend.php','xmail.local.php']]
        files.append((ROOT/'dist/.htaccess',WEBROOT+'/.htaccess'))
    for name in ['i18n.php', 'pricing.php', 'language-preference.php', 'seo.php', 'settings.json', 'order-email.php', 'notifications.php', 'turnstile.php','xmail-imap.php','xmail-backend.php']:
        if not xmail_only: files.append((ROOT / name, '/' + name))

    if not xmail_only and (ROOT / 'smtp.local.php').exists():
        files.append((ROOT / 'smtp.local.php', '/smtp.local.php'))
    if not xmail_only and (ROOT / 'turnstile.local.php').exists():
        files.append((ROOT / 'turnstile.local.php', '/turnstile.local.php'))
    if not xmail_only and (ROOT / 'xmail.local.php').exists():
        files.append((ROOT / 'xmail.local.php', '/xmail.local.php'))
    if not xmail_only and (ROOT / 'vendor/autoload.php').exists():
        runtime = [ROOT / 'vendor/autoload.php']
        runtime += [file for file in (ROOT / 'vendor/composer').glob('*') if file.is_file()]
        runtime += [file for file in (ROOT / 'vendor/phpmailer/phpmailer/src').glob('*.php') if file.is_file()]
        runtime += [ROOT / 'vendor/phpmailer/phpmailer/LICENSE']
        files += [(file, '/' + file.relative_to(ROOT).as_posix()) for file in runtime]

    # Back up every target that already exists, plus the original HTML landing page.
    for remote in [remote for _, remote in files] + [WEBROOT + '/index.html', WEBROOT+'/index.php']:
        target = backup / remote.lstrip('/')
        try:
            buffer = io.BytesIO()
            ftp.retrbinary('RETR ' + remote, buffer.write)
        except ftplib.error_perm as error:
            if not str(error).startswith('550'): raise
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(buffer.getvalue())
    print('Existing files backed up: ' + str(backup), flush=True)
    original_htaccess = backup / 'public_html' / '.htaccess'
    handler = ''
    if original_htaccess.exists():
        for line in original_htaccess.read_text(encoding='utf-8').splitlines():
            if line.strip().startswith('AddHandler '): handler += line + '\n'
    directories = {'/', WEBROOT}
    manifest = []
    # Load dependencies/assets first; switch routing and entry point last.
    files.sort(key=lambda pair: (2 if pair[1] == WEBROOT + '/index.php' else 1 if pair[1] in [WEBROOT + '/.htaccess', WEBROOT + '/api/order.php', '/notifications.php'] else 0, pair[1]))
    for local, remote in files:
        parent = pathlib.PurePosixPath(remote).parent
        for directory in reversed([parent] + list(parent.parents)):
            path = str(directory)
            if path in directories: continue
            try: ftp.mkd(path)
            except ftplib.error_perm as error:
                if not str(error).startswith('550'): raise
                ftp.cwd(path)  # Verify that an already-existing directory is accessible.
                ftp.cwd('/')
            directories.add(path)
        payload = local.read_bytes()
        if remote == WEBROOT + '/.htaccess':
            if xmail_only:
                if not original_htaccess.exists(): raise RuntimeError('Existing host routing required for xmail-only deploy')
                payload = original_htaccess.read_bytes()
                denial=b'RewriteRule ^(?:xmail(?:\\.local|-backend|-imap)\\.php|var/xmail[^/]*) - [F,L]'
                if denial not in payload:
                    if b'RewriteEngine On' not in payload: raise RuntimeError('Review existing rewrite setup')
                    payload=payload.replace(b'RewriteEngine On',b'RewriteEngine On\n'+denial,1)
                if b'RewriteRule ^xmail(?:/.*)?$ xmail/index.php' not in payload:
                    rule=b'\n# XMail private reader\nRewriteRule ^xmail/(?:xmail\\.(?:css|js)|index\\.php)$ - [L]\nRewriteRule ^xmail(?:/.*)?$ xmail/index.php [L,QSA]\n'
                    if b'RewriteEngine On' not in payload: raise RuntimeError('Review existing rewrite setup')
                    payload=payload.replace(b'RewriteEngine On',b'RewriteEngine On'+rule,1)
            else: payload = handler.encode() + payload
        existing = backup / remote.lstrip('/')
        if existing.exists() and existing.read_bytes() == payload:
            if remote in ['/smtp.local.php', '/turnstile.local.php', '/xmail.local.php']: ftp.sendcmd('SITE CHMOD 600 ' + remote)
            manifest.append({'remote': remote, 'sha256': hashlib.sha256(payload).hexdigest(), 'unchanged': True})
            continue
        temporary = remote + '.deploy-' + stamp
        ftp.storbinary('STOR ' + temporary, io.BytesIO(payload))
        check = io.BytesIO()
        ftp.retrbinary('RETR ' + temporary, check.write)
        if hashlib.sha256(check.getvalue()).digest() != hashlib.sha256(payload).digest():
            raise RuntimeError('Remote verification failed: ' + remote)
        if remote in ['/smtp.local.php', '/turnstile.local.php', '/xmail.local.php']: ftp.sendcmd('SITE CHMOD 600 ' + temporary)
        ftp.rename(temporary, remote)
        manifest.append({'remote': remote, 'sha256': hashlib.sha256(payload).hexdigest()})
        if len(manifest) % 15 == 0: print('Uploaded and verified: ' + str(len(manifest)), flush=True)
    (backup / 'deployment-manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    if xmail_only:
        for name in ['index.php','index.html']:
            original=backup/'public_html'/name
            if original.exists():
                current=io.BytesIO();ftp.retrbinary('RETR '+WEBROOT+'/'+name,current.write)
                if current.getvalue()!=original.read_bytes():raise RuntimeError('Homepage changed during xmail-only deployment')
        print('Existing production homepage preserved byte-for-byte.',flush=True)
    ftp.quit()
    print('DEPLOYED: ' + str(len(manifest)) + ' verified files. Backup: ' + str(backup), flush=True)

if __name__ == '__main__': deploy()
