const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, 'dist/locales');
const registry = JSON.parse(fs.readFileSync(path.join(root, 'languages.json'), 'utf8'));
const base = JSON.parse(fs.readFileSync(path.join(root, 'en.json'), 'utf8'));
const htmlKeys = new Set(['heroTitle','catalogTitle','howTitle','worldTitle','faqTitle']);
let failures = 0;
const codes = new Set();
for (const entry of registry.languages) {
  if(codes.has(entry.code)) { console.error('Duplicate language: '+entry.code); failures++; }
  codes.add(entry.code);
  if(!entry.enabled) continue;
  const translation = JSON.parse(fs.readFileSync(path.join(root, entry.code + '.json'), 'utf8'));
  const errors = [];
  for(const [key, value] of Object.entries(base)) {
    const text = translation[key];
    if(typeof text !== 'string' || !text.trim()) { errors.push('Missing: '+key); continue; }
    const tokens = s => (s.match(/\{[a-zA-Z]+\}/g)||[]).sort().join(',');
    if(tokens(text)!==tokens(value)) errors.push('Placeholders: '+key);
    for (const token of ['USDT', 'USD', 'VAMPIR', 'Discord', 'Telegram']) {
      const count = s => s.split(token).length - 1;
      if(count(text)!==count(value)) errors.push('Changed brand/currency '+token+': '+key);
    }
    if(htmlKeys.has(key) && /<\/?(?!em\b|br\b)[a-z]|<(?:em|br)\s+[^>]*\w+=/i.test(text)) errors.push('Unsupported HTML: '+key);
  }
  for(const key of Object.keys(translation)) if(!(key in base)) errors.push('Unknown: '+key);
  failures += errors.length;
  console.log(entry.code + ': ' + (errors.length ? errors.join('; ') : Object.keys(base).length+' keys OK'));
}
if(!registry.languages.some(entry=>entry.code===registry.default && entry.enabled)) {failures++;console.error('Default language disabled');}
process.exitCode = failures ? 1 : 0;
