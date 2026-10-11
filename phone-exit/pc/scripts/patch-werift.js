import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
const root=fileURLToPath(new URL('../node_modules/werift/',import.meta.url));
const pkg=JSON.parse(fs.readFileSync(root+'package.json','utf8'));
if(pkg.version!=='0.25.0')throw Error('Review late DCEP ACK patch for new werift version');
// A cancelled stream can be reset before its DCEP ACK arrives. Drop that ACK;
// reopening a closing channel or rejecting this receive promise kills unrelated flows.
for(const relative of ['lib/index.mjs','lib/webrtc/src/transport/sctp.js']) {
 const p=root+relative;let s=fs.readFileSync(p,'utf8');
 const original=/if \(!channel\) \{\s*throw new Error\("channel not found"\);\s*\}/g;
 const replacement='if (!channel || channel.readyState === "closing" || channel.readyState === "closed") { return; } // Phone Exit: late DCEP ACK';
 if(s.includes('// Phone Exit: late DCEP ACK'))continue;
 if(!original.test(s))throw Error('Expected werift ACK guard missing');
 s=s.replace(original,replacement);fs.writeFileSync(p,s);
}
