import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch


class RegistrationMailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('registration_mail',
            Path(__file__).parent / 'vampir-headless/nid-mail-code.py')
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def message(self, body, sender='noreply@netmarble.net', recipient='fixture@vampir.top', subject=None):
        return ('From: Netmarble <' + sender + '>\r\nTo: ' + recipient + '\r\nSubject: ' +
            (subject or '[Netmarble] Please verify your identity to continue with account creation') +
            '\r\nContent-Type: text/html; charset=utf-8\r\n\r\n' + body).encode()

    def test_observed_five_digit_format_and_html(self):
        self.assertEqual(self.module.registration_code(self.message('<b>12345</b>'), 'fixture@vampir.top'), '12345')
        self.assertEqual(self.module.registration_code(self.message('<b>12&#51;45</b>'), 'fixture@vampir.top'), '12345')
        self.assertEqual(self.module.registration_code(self.message('12345 and 12345'), 'fixture@vampir.top'), '12345')

    def test_wrong_message_and_ambiguous_codes_are_rejected(self):
        messages = [self.message('12345', sender='noreply@unrelated.invalid'),
            self.message('12345', recipient='other@vampir.top'), self.message('12345', subject='Password reset'),
            self.message('12345 54321'), self.message('123456'), self.message('1234'), b'x' * 131073]
        for message in messages:
            self.assertIsNone(self.module.registration_code(message, 'fixture@vampir.top'))

    def test_only_explicit_user_mail_domain_is_accepted(self):
        for address in ('fixture@other.invalid', 'two@@vampir.top', 'x\n@vampir.top'):
            with self.assertRaises(ValueError): self.module.RegistrationMailbox(address, 'unused')

    def test_uid_baseline_skips_old_mail_and_reads_without_marking_seen(self):
        client = Mock()
        client.select.return_value = ('OK', [b'2'])
        client.response.return_value = ('UIDNEXT', [b'10'])
        def uid(operation, *args):
            if operation == 'search': return ('OK', [b'9 10'])
            self.assertEqual((operation, args), ('fetch', (b'10', '(BODY.PEEK[]<0.131072>)')))
            return ('OK', [(b'wire metadata', self.message('12345'))])
        client.uid.side_effect = uid
        with patch.object(self.module.imaplib, 'IMAP4_SSL', return_value=client) as factory:
            mailbox = self.module.RegistrationMailbox('fixture@vampir.top', 'fixture-password')
            self.assertEqual(mailbox.get_code(), '12345')
            mailbox.close()
        client.select.assert_called_once_with('INBOX', readonly=True)
        client.logout.assert_called_once()
        self.assertTrue(factory.call_args.kwargs['ssl_context'].check_hostname)


if __name__ == '__main__': unittest.main()
