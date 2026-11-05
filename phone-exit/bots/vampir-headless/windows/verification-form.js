(function (input) {
    'use strict';
    if (location.origin !== 'https://profile-auth-view.netmarble.com') return 'waiting';
    const path = location.pathname;
    const device = input.purpose === 'device-registration';
    if (device ? !/^\/secure\/device\/(?:new|additional)\/step[1-5]$/.test(path)
        : !/^\/restriction\/release\/email\/step[1-3]$/.test(path)) return 'waiting';
    const body = document.body?.innerText || '';
    if (/an abnormal pattern/i.test(body)) return 'abnormal_pattern';
    const visible = element => element.getClientRects().length > 0;
    if (Array.from(document.querySelectorAll('iframe[title]')).some(element =>
        visible(element) && /recaptcha challenge/i.test(element.title))) return 'captcha_required';
    const click = label => {
        const buttons = Array.from(document.querySelectorAll('button')).filter(button =>
            visible(button) && !button.disabled && button.textContent.trim() === label);
        if (buttons.length !== 1) return false;
        buttons[0].click();
        return true;
    };
    const masked = body.match(/[\w.+-]*\*+[\w.*+-]*@[\w.-]+/gi) || [];
    const inputs = Array.from(document.querySelectorAll('input')).filter(visible);
    for (const element of inputs) {
        if (/^[\w.+-]*\*+[\w.*+-]*@[\w.-]+$/i.test(element.value)) masked.push(element.value);
    }
    const accountMatches = masked.length > 0 && masked.every(value => {
        const expression = value.toLowerCase().split(/\*+/).map(part =>
            part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('[^@]+');
        return new RegExp('^' + expression + '$').test(input.email.toLowerCase());
    });
    const enteringCode = device ? body.includes('Enter Verification Code') :
        path === '/restriction/release/email/step2' && body.includes('Verify with Email');
    if (enteringCode && /^\d{5}$/.test(input.code)) {
        if (!accountMatches || input.actions.includes('code_submitted')) return 'waiting';
        const fields = inputs.filter(element => !element.disabled && !element.readOnly &&
            element.placeholder === 'Enter only numbers.');
        if (fields.length !== 1) return 'waiting';
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(fields[0], input.code);
        fields[0].dispatchEvent(new Event('input', {bubbles: true}));
        return click('Confirm') ? 'code_submitted' : 'waiting';
    }
    if (input.actions.includes('code_submitted') && !input.actions.includes('completion_clicked') &&
            device && body.includes('Device Registered')) {
        return click('Confirm') ? 'completion_clicked' : 'waiting';
    }
    if (!input.actions.includes('mail_requested') && body.includes('Verify with Email') && accountMatches) {
        return click('Send Verification Code') ? 'mail_requested' : 'waiting';
    }
    if (device && !input.actions.includes('device_name') && body.includes('Set Device Name') &&
        inputs.some(element => element.value.trim())) return click('Confirm') ? 'device_name' : 'waiting';
    if (device && !input.actions.includes('device_start') && body.includes('Device Registration Required')) {
        return click('Next') ? 'device_start' : 'waiting';
    }
    return 'waiting';
})
