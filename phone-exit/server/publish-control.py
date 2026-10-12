"""Run after APK build/lint/tests; FTP credentials arrive as JSON on stdin only.
Deploy only a new dedicated subdirectory, never the existing signal.php.
"""
import ftplib
import io
import json
from pathlib import Path
import ssl
import sys
import urllib.request
import urllib.error

root = Path(__file__).resolve().parents[1]
config = json.load(sys.stdin)
ftp = ftplib.FTP_TLS(context=ssl.create_default_context(), timeout=30)
try:
    # Hosting's certificate is issued to this name, not demochko.com.
    ftp.connect("skm351.hostsila.org", 21)
    ftp.login(config["user"], config["password"])
    ftp.prot_p()
    def ensure(path):
        try:
            ftp.mkd(path)
        except ftplib.error_perm:
            ftp.cwd(path)
            ftp.cwd("/")
    ensure("/phone-exit-api")
    def put(local, target):
        with local.open("rb") as stream:
            ftp.storbinary("STOR " + target, stream, blocksize=65536)
    if config.get("release", True):
        ensure("/phone-exit-api/private")
        ensure("/phone-exit-api/private/releases")
        put(root / "server/control-private.htaccess", "/phone-exit-api/private/.htaccess")
        # Required before transferring any personal APK/private release.
        ftp.storbinary("STOR /phone-exit-api/private/protection-check.txt", io.BytesIO(b"private"))
        url = "https://demochko.com/hosting-webrtc-probe/phone-exit-api/private/protection-check.txt"
        protected = False
        try:
            urllib.request.urlopen(url, timeout=20).close()
        except urllib.error.HTTPError as error:
            protected = error.code == 403
        finally:
            ftp.delete("/phone-exit-api/private/protection-check.txt")
        if not protected:
            raise RuntimeError("Private directory must return HTTP 403")
    else:
        # Public source-only fix: no APK/private files or protection changes.
        try:
            ftp.delete("/phone-exit-api/private/protection-check.txt")
        except ftplib.error_perm:
            pass
    put(root / "server/control.php", "/phone-exit-api/control.php.next")
    ftp.rename("/phone-exit-api/control.php.next", "/phone-exit-api/control.php")
    if config.get("release", True):
        manifests = list((root / ".tools/update-release").glob("*.json"))
        if len(manifests) != 1:
            raise RuntimeError("Exactly one private release expected")
        manifest = manifests[0]
        apk = manifest.with_suffix(".apk")
        # APK first, manifest last. Existing same-version releases are immutable.
        meta = json.loads(manifest.read_text())
        remote = "/phone-exit-api/private/releases/" + manifest.name
        data = io.BytesIO()
        try:
            ftp.retrbinary("RETR " + remote, data.write)
        except ftplib.error_perm:
            pass
        if data.getvalue():
            old = json.loads(data.getvalue())
            if old["versionCode"] >= meta["versionCode"] and old != meta:
                raise RuntimeError("Release version must increase")
        put(apk, "/phone-exit-api/private/releases/" + apk.name + ".next")
        ftp.rename("/phone-exit-api/private/releases/" + apk.name + ".next", "/phone-exit-api/private/releases/" + apk.name)
        put(manifest, remote + ".next")
        ftp.rename(remote + ".next", remote)
    print("Published dedicated control API. " + ("Private directory HTTP 403 verified. " if config.get("release",True) else "No private release transferred. ") + "Legacy files untouched.")
finally:
    ftp.close()
