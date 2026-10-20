(function (input) {
    'use strict';
    if (location.origin !== 'https://members.netmarble.com') return null;
    const advance = () => {
    const visible = element => element.getClientRects().length > 0;
    const controls = Array.from(document.querySelectorAll('button,a,input,[role="button"]'))
        .filter(visible);
    const state = input.state || {};
    if (location.pathname === '/auth/signup/email/input' && state.email_sent &&
        document.body.innerText.includes('Verification emails can only be sent once every'))
        return {...state, stopped: 'mail_rate_limited'};
    const setValue = (element, value) => {
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(element, value);
        element.dispatchEvent(new Event('input', {bubbles: true}));
    };
    const button = text => controls.filter(element => element.tagName === 'BUTTON' &&
        element.textContent.trim() === text && !element.disabled);
    if (location.pathname === '/auth/signup/email/input') {
        const emails = controls.filter(element => element.tagName === 'INPUT' && element.placeholder === 'Enter email');
        if (emails.length === 1 && !state.email_sent) {
            if (emails[0].value !== input.email) {
                if (state.email_filled) return {...state, stopped: 'email_changed'};
                setValue(emails[0], input.email);
                return {...state, email_filled: true};
            }
            const send = button('Send verification email');
            if (send.length === 1) {
                send[0].click();
                return {...state, email_sent: true};
            }
        }
    }
    if (location.pathname.startsWith('/auth/signup/') && state.email_sent) {
        const passwords = controls.filter(element => element.tagName === 'INPUT' && element.type === 'password');
        const codes = controls.filter(element => element.tagName === 'INPUT' &&
            location.pathname === '/auth/signup/email/verify' &&
            element.type === 'text' && element.placeholder === 'Enter only numbers.');
        if (codes.length === 1 && !state.code_submitted) {
            if (!input.code) return {...state, need_code: true};
            if (codes[0].value !== input.code) {
                if (state.code_filled) return {...state, stopped: 'code_changed'};
                setValue(codes[0], input.code);
                return {...state, need_code: false, code_filled: true};
            }
            const next = button('Confirm Verification Code');
            if (next.length === 1) {
                next[0].click();
                return {...state, need_code: false, code_submitted: true};
            }
        }
        if (location.pathname === '/auth/signup/password/input' && passwords.length === 2 && !state.password_submitted) {
            if (passwords.some(element => element.value !== input.password)) {
                if (state.password_filled) return {...state, stopped: 'password_changed'};
                passwords.forEach(element => setValue(element, input.password));
                return {...state, password_filled: true};
            }
            const next = button('Next');
            if (next.length === 1) {
                next[0].click();
                return {...state, password_submitted: true};
            }
        }
        if (state.password_submitted && document.body.innerText.includes('Account Registration Complete')) {
            return {...state, complete: true};
        }
    }
    if (location.pathname === '/auth/signup/terms') {
        const required = ['[Required]Agree to Terms of Service', '[Required]Agree to Privacy Policy'];
        const optionalText = '[Optional]Marketing Consent';
        const boxes = controls.filter(element => element.type === 'checkbox');
        const bindings = boxes.map(element => {
            let parent = element.parentElement;
            while (parent && parent.querySelectorAll('input[type="checkbox"]').length === 1) {
                if (required.includes(parent.textContent.trim()) || parent.textContent.trim() === optionalText)
                    return {element, text: parent.textContent.trim()};
                parent = parent.parentElement;
            }
            return null;
        }).filter(Boolean);
        if (bindings.length === 3 && required.every(text => bindings.some(binding => binding.text === text)) &&
            bindings.filter(binding => binding.text === optionalText).length === 1) {
            const optional = bindings.find(binding => binding.text === optionalText);
            if (optional.element.checked) {
                optional.element.click();
                return {opened_signup: true, marketing_disabled: true};
            }
            const unchecked = bindings.filter(binding => required.includes(binding.text) && !binding.element.checked);
            if (unchecked.length) {
                unchecked.forEach(binding => binding.element.click());
                return {opened_signup: true, terms_checked: true};
            }
            const agree = controls.filter(element => element.tagName === 'BUTTON' &&
                element.textContent.trim() === 'Agree' && !element.disabled);
            if (agree.length === 1 && !state.terms_submitted) {
                agree[0].click();
                return {opened_signup: true, terms_submitted: true};
            }
        }
    }
    const emailButtons = controls.filter(element => element.tagName === 'BUTTON' &&
        element.textContent.trim() === 'Sign in with email' && !element.disabled);
    if (location.pathname === '/auth/signin' && emailButtons.length === 1 && !state.opened_email) {
        emailButtons[0].click();
        return {opened_email: true};
    }
    const links = Array.from(document.querySelectorAll('a,button,span,div')).filter(visible)
        .filter(element => element.textContent.trim() === 'Create an Account' &&
            !Array.from(element.children).some(child => child.textContent.trim() === 'Create an Account'));
    if (location.pathname === '/auth/signin/email' && links.length === 1 && !state.opened_signup) {
        links[0].click();
        return {opened_signup: true};
    }
    return state;
    };
    const result = advance();
    return result && {...result, path: location.pathname};
})
