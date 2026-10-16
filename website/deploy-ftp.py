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

ROOT = pathlib.Path(__file__).resolve().parent
HOST = 'dd.rehost.com.ua'
USER = 'ftp@vampir.top'
WEBROOT = '/public_html'

def deploy():
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
    for name in ['i18n.php', 'pricing.php', 'language-preference.php', 'seo.php', 'settings.json', 'notifications.php']:
        files.append((ROOT / name, '/' + name))

    if (ROOT / 'smtp.local.php').exists():
        files.append((ROOT / 'smtp.local.php', '/smtp.local.php'))
    if (ROOT / 'vendor/autoload.php').exists():
        runtime = [ROOT / 'vendor/autoload.php']
        runtime += [file for file in (ROOT / 'vendor/composer').glob('*') if file.is_file()]
        runtime += [file for file in (ROOT / 'vendor/phpmailer/phpmailer/src').glob('*.php') if file.is_file()]
        runtime += [ROOT / 'vendor/phpmailer/phpmailer/LICENSE']
        files += [(file, '/' + file.relative_to(ROOT).as_posix()) for file in runtime]

    # Back up every target that already exists, plus the original HTML landing page.
    for remote in [remote for _, remote in files] + [WEBROOT + '/index.html']:
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
    files.sort(key=lambda pair: (2 if pair[1] == WEBROOT + '/index.php' else 1 if pair[1] in [WEBROOT + '/.htaccess', '/notifications.php'] else 0, pair[1]))
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
        if remote == WEBROOT + '/.htaccess': payload = handler.encode() + payload
        existing = backup / remote.lstrip('/')
        if existing.exists() and existing.read_bytes() == payload:
            if remote == '/smtp.local.php': ftp.sendcmd('SITE CHMOD 600 ' + remote)
            manifest.append({'remote': remote, 'sha256': hashlib.sha256(payload).hexdigest(), 'unchanged': True})
            continue
        temporary = remote + '.deploy-' + stamp
        ftp.storbinary('STOR ' + temporary, io.BytesIO(payload))
        check = io.BytesIO()
        ftp.retrbinary('RETR ' + temporary, check.write)
        if hashlib.sha256(check.getvalue()).digest() != hashlib.sha256(payload).digest():
            raise RuntimeError('Remote verification failed: ' + remote)
        if remote == '/smtp.local.php': ftp.sendcmd('SITE CHMOD 600 ' + temporary)
        ftp.rename(temporary, remote)
        manifest.append({'remote': remote, 'sha256': hashlib.sha256(payload).hexdigest()})
        if len(manifest) % 15 == 0: print('Uploaded and verified: ' + str(len(manifest)), flush=True)
    (backup / 'deployment-manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    ftp.quit()
    print('DEPLOYED: ' + str(len(manifest)) + ' verified files. Backup: ' + str(backup), flush=True)

if __name__ == '__main__': deploy()
