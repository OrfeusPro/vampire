(function (credentials) {
    'use strict';
    // Only the official top-level sign-in routes may receive credentials.
    if (location.origin !== 'https://members.netmarble.com' ||
        !['/auth/signin', '/auth/signin/email'].includes(location.pathname)) return 'waiting';
    const buttons = Array.from(document.querySelectorAll('button'))
        .filter(button => button.textContent.trim() === 'Sign in with email' && !button.disabled);
    if (buttons.length !== 1) return 'waiting';
    if (location.pathname === '/auth/signin') {
        if (credentials.emailOpened) return 'waiting';
        buttons[0].click();
        return 'opened_email';
    }
    const passwords = Array.from(document.querySelectorAll('input[type="password"]'));
    const emails = Array.from(document.querySelectorAll('input'))
        .filter(input => ['text', 'email'].includes(input.type) && input.placeholder === 'Email');
    if (passwords.length !== 1 || emails.length !== 1 ||
        passwords[0].disabled || emails[0].disabled) return 'waiting';
    if (emails[0].value !== credentials.email || passwords[0].value !== credentials.password) {
        if (credentials.filled) return 'form_changed';
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
        setter.call(emails[0], credentials.email);
        emails[0].dispatchEvent(new Event('input', {bubbles: true}));
        setter.call(passwords[0], credentials.password);
        passwords[0].dispatchEvent(new Event('input', {bubbles: true}));
        return 'filled';
    }
    buttons[0].click();
    return 'submitted';
})
