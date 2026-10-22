(function () {
    'use strict';
    if (location.origin !== 'https://members.netmarble.com' ||
        !(location.pathname === '/auth' || location.pathname.startsWith('/auth/')) ||
        location.pathname.startsWith('/auth/signup')) return 'unknown';
    // Observe only fixed failure labels, including after the single form submission.
    const visible = Array.from(document.querySelectorAll('h1,h2,h3,[role="alert"],[role="dialog"]'))
        .filter(element => element.getClientRects().length > 0);
    for (const element of visible) {
        const text = element.innerText;
        if (typeof text !== 'string' || text.length > 4096) continue;
        if (text.split('\n').some(line => /^Login Failed[.!]?$/i.test(line.trim()))) return 'login_failed';
    }
    const body = document.body?.innerText;
    if (typeof body === 'string' && body.length <= 8192 &&
        body.split('\n').some(line => /^Login Failed[.!]?$/i.test(line.trim()))) return 'login_failed';
    return 'waiting';
})
