"""Read a fresh Netmarble registration code from the explicitly selected mailbox.

TLS verification, read-only INBOX and BODY.PEEK; no message/code persistence.
The sender/header filter selects a message, not a cryptographic sender proof.
"""
import email
from email.policy import default
from email.utils import getaddresses, parseaddr
from html import unescape
import imaplib
import re
import ssl
import time


def registration_code(raw, address):
    if not isinstance(raw, bytes) or len(raw) > 131072: return None
    message = email.message_from_bytes(raw, policy=default)
    if parseaddr(str(message['From']))[1].lower() != 'noreply@netmarble.net': return None
    if address.lower() not in {value.lower() for _, value in getaddresses(message.get_all('To', []))}: return None
    if str(message['Subject']) != '[Netmarble] Please verify your identity to continue with account creation':
        return None
    text = '\n'.join(part.get_content() for part in message.walk()
        if not part.is_multipart() and part.get_content_type() in ('text/plain', 'text/html'))
    text = unescape(re.sub('<[^>]*>', ' ', text))
    candidates = set(re.findall(r'(?<![0-9])([0-9]{5})(?![0-9])', text))
    return candidates.pop() if len(candidates) == 1 else None


class RegistrationMailbox:
    """Explicit mail.vampir.top:143 with verified STARTTLS before credentials."""
    def __init__(self, address, password):
        if (type(address) is not str or address.count('@') != 1 or
                not address.endswith('@vampir.top') or any(c.isspace() for c in address)):
            raise ValueError('Explicit bot mailbox required')
        self.address = address.lower()
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
            self.seen = set()
        except BaseException:
            self.close()
            raise

    def get_code(self, timeout=120):
        if type(timeout) is not int or not 1 <= timeout <= 120: raise ValueError('Invalid mail timeout')
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.client.noop()
            status, data = self.client.uid('search', None, 'UID', str(self.first_uid) + ':*')
            if status != 'OK': raise RuntimeError('Registration mailbox search failed')
            uids = data[0].split()
            if len(uids) > 100: raise RuntimeError('Registration mailbox message limit')
            for uid in sorted(uids, key=int, reverse=True):
                if int(uid) < self.first_uid or uid in self.seen: continue
                self.seen.add(uid)
                status, parts = self.client.uid('fetch', uid, '(BODY.PEEK[]<0.131072>)')
                if status != 'OK': continue
                raw = b''.join(part[1] for part in parts if isinstance(part, tuple))
                code = registration_code(raw, self.address)
                if code: return code
            time.sleep(min(3, max(0, deadline - time.monotonic())))
        raise RuntimeError('No unique fresh registration code received')

    def close(self):
        try: self.client.logout()
        except (OSError, imaplib.IMAP4.error): pass
