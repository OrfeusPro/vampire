"""Read a fresh Netmarble code of a known purpose from the selected mailbox.

TLS verification, read-only INBOX and BODY.PEEK; no message/code persistence.
The sender/header filter selects a message, not a cryptographic sender proof.
"""
import email
from email.policy import default
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html import unescape
import imaplib
import re
import ssl
import time


SUBJECTS = {
    'account-creation': '[Netmarble] Please verify your identity to continue with account creation',
    'device-registration': '[Netmarble] Please verify your email for device registration.',
    'account-protection': '[Netmarble] Please complete email verification to protect your account.',
}


def registration_code(raw, address, *, purpose='account-creation'):
    subject = SUBJECTS[purpose]
    if not isinstance(raw, bytes) or len(raw) > 131072: return None
    message = email.message_from_bytes(raw, policy=default)
    if parseaddr(str(message['From']))[1].lower() != 'noreply@netmarble.net': return None
    if address.lower() not in {value.lower() for _, value in getaddresses(message.get_all('To', []))}: return None
    if str(message['Subject']) != subject:
        return None
    text = '\n'.join(part.get_content() for part in message.walk()
        if not part.is_multipart() and part.get_content_type() in ('text/plain', 'text/html'))
    text = unescape(re.sub('<[^>]*>', ' ', text))
    candidates = set(re.findall(r'(?<![0-9])([0-9]{5})(?![0-9])', text))
    return candidates.pop() if len(candidates) == 1 else None


class RegistrationMailbox:
    """Explicit mail.vampir.top:143 with verified STARTTLS before credentials."""
    def __init__(self, address, password, *, purpose='account-creation'):
        if (type(address) is not str or address.count('@') != 1 or
                not address.endswith('@vampir.top') or any(c.isspace() for c in address)):
            raise ValueError('Explicit bot mailbox required')
        self.address = address.lower()
        if purpose not in SUBJECTS:
            raise ValueError('Unknown Netmarble mail purpose')
        self.purpose = purpose
        self.verification = purpose != 'account-creation'
        self.client = imaplib.IMAP4('mail.vampir.top', 143, timeout=15)
        try:
            self.client.starttls(ssl_context=ssl.create_default_context())
            self.client.login(address, password)
            status, _ = self.client.select('INBOX', readonly=True)
            if status != 'OK': raise RuntimeError('Cannot open registration mailbox')
            _, values = self.client.response('UIDNEXT')
            if len(values) != 1 or not values[0] or not values[0].isdigit():
                raise RuntimeError('Missing mailbox UID baseline')
            self.first_uid = int(values[0])
            if self.verification:
                self.uid_validity = self._uid_validity()
                self.baseline_utc = time.time()
                self.deadline = time.monotonic() + 600
            self.seen = set()
        except BaseException:
            self.close()
            raise

    def _uid_validity(self):
        _, values = self.client.response('UIDVALIDITY')
        if len(values) != 1 or not values[0] or not values[0].isdigit():
            raise RuntimeError('Missing mailbox UID validity')
        return int(values[0])

    def _recent(self, parts):
        headers = [part[0] for part in parts if isinstance(part, tuple)]
        if len(headers) != 1:
            return False
        match = re.search(rb'\bINTERNALDATE "(\s?\d{1,2})-([A-Za-z]{3})-(\d{4} \d\d:\d\d:\d\d [+-]\d{4})"', headers[0])
        if not match:
            return False
        try:
            delivered = parsedate_to_datetime(b' '.join(match.groups()).decode('ascii')).timestamp()
        except (ValueError, OverflowError):
            return False
        now = time.time()
        return self.baseline_utc - 2 <= delivered <= now + 30 and now - delivered <= 600

    def get_code(self, timeout=120, *, cancelled=None):
        maximum = 600 if self.verification else 120
        if type(timeout) is not int or not 1 <= timeout <= maximum: raise ValueError('Invalid mail timeout')
        deadline = time.monotonic() + timeout
        if self.verification:
            deadline = min(deadline, self.deadline)
        query = '(INTERNALDATE BODY.PEEK[]<0.131072>)' if self.verification else '(BODY.PEEK[]<0.131072>)'
        while time.monotonic() < deadline:
            if cancelled is not None and cancelled():
                raise RuntimeError('Verification form closed')
            self.client.noop()
            if self.verification:
                _, values = self.client.response('UIDVALIDITY')
                if values != [None] and values != [str(self.uid_validity).encode('ascii')]:
                    raise RuntimeError('Mailbox UID validity changed')
            status, data = self.client.uid('search', None, 'UID', str(self.first_uid) + ':*')
            if status != 'OK': raise RuntimeError('Registration mailbox search failed')
            uids = data[0].split()
            if len(uids) > 100: raise RuntimeError('Registration mailbox message limit')
            candidates = set()
            for uid in sorted(uids, key=int, reverse=True):
                if int(uid) < self.first_uid or uid in self.seen: continue
                self.seen.add(uid)
                status, parts = self.client.uid('fetch', uid, query)
                if status != 'OK': continue
                if self.verification and not self._recent(parts): continue
                raw = b''.join(part[1] for part in parts if isinstance(part, tuple))
                code = registration_code(raw, self.address, purpose=self.purpose)
                if code:
                    if not self.verification: return code
                    candidates.add(code)
            if len(candidates) > 1: raise RuntimeError('Multiple fresh Netmarble verification codes')
            if candidates and time.monotonic() < deadline: return candidates.pop()
            time.sleep(min(3, max(0, deadline - time.monotonic())))
        raise RuntimeError('No unique fresh registration code received')

    def close(self):
        try: self.client.logout()
        except (OSError, imaplib.IMAP4.error): pass
