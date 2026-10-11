import test from 'node:test';
import assert from 'node:assert/strict';
import {createAccount} from '../src/account.js';
import {sealProfile,openProfile,validateProfile} from '../src/account-transfer.js';
const password='длинный пароль для переноса';
const profile=()=>({version:1,account:createAccount(),phones:[{id:'a'.repeat(32),token:'b'.repeat(64),name:'Samsung'}]});
test('encrypted transfer preserves account, phones and blocked ids without plaintext keys',()=>{
  const p=profile();p.account.blocked=['c'.repeat(32)];const box=sealProfile(p,password);
  assert.deepEqual(openProfile(box,password),p);assert.ok(!box.includes(p.account.feedToken));
  assert.notEqual(box,sealProfile(p,password));
});
test('wrong password, tampering and unsupported parameters fail',()=>{
  const box=sealProfile(profile(),password);assert.throws(()=>openProfile(box,'another long password'));
  for(const field of ['data','tag','iv','salt']){const b=JSON.parse(box);b[field]=(b[field][0]==='A'?'B':'A')+b[field].slice(1);assert.throws(()=>openProfile(JSON.stringify(b),password));}
  const b=JSON.parse(box);b.kdf='scrypt-unlimited';assert.throws(()=>openProfile(JSON.stringify(b),password));
  assert.throws(()=>openProfile('x'.repeat(524289),password));assert.throws(()=>sealProfile(profile(),'short'));
});
test('reject inconsistent account keys, duplicate phones and oversized lists',()=>{
  const p=profile();p.account.publicKey=createAccount().publicKey;assert.throws(()=>validateProfile(p));
  const q=profile();q.phones.push(q.phones[0]);assert.throws(()=>validateProfile(q));
  const r=profile();r.account.blocked=['bad'];assert.throws(()=>validateProfile(r));
  const s=profile();s.phones=Array(257).fill(s.phones[0]);assert.throws(()=>validateProfile(s));
});
