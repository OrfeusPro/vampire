import json
from pathlib import Path
import subprocess
import unittest


class NidSignInFormTests(unittest.TestCase):
    def test_dom_contract_and_one_submission(self):
        source = (Path(__file__).parent / 'vampir-headless/windows/nid-sign-in.js').read_text('utf-8')
        fixture = r'''
const vm = require('node:vm');
const source = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
class Input {
  constructor(type, placeholder) { this.type=type; this.placeholder=placeholder; this.disabled=false; this.saved=''; this.events=[]; }
  get value() { return this.saved; }
  set value(value) { this.saved=value; }
  dispatchEvent(event) { this.events.push(event.type); }
}
function scenario(origin, path, ambiguous=false) {
 const email=new Input('text','Email'), password=new Input('password','Password');
 let clicks=0;
 const button={textContent:'Sign in with email',disabled:false,click(){clicks++;}};
 const inputs=[email,password];
 const context={location:{origin,pathname:path},HTMLInputElement:Input,Event:class {constructor(type){this.type=type;}},
  document:{querySelectorAll(selector){
   if(selector==='button')return ambiguous?[button,button]:[button];
   if(selector==='input[type="password"]')return [password];
   if(selector==='input')return inputs;
   throw Error('Unexpected selector');
  }}};
 const run=vm.runInNewContext(source,context);
 const c={email:'fixture@example.invalid',password:'fixture-password',emailOpened:false,filled:false};
 const first=run(c);
 if(first==='filled')c.filled=true;
 if(first==='opened_email')c.emailOpened=true;
 const second=run(c);
 return {first,second,clicks,events:email.events.concat(password.events),filled:email.value===c.email};
}
const result={form:scenario('https://members.netmarble.com','/auth/signin/email'),
 select:scenario('https://members.netmarble.com','/auth/signin'),
 wrongOrigin:scenario('https://other.invalid','/auth/signin/email'),
 signup:scenario('https://members.netmarble.com','/auth/signup/password/input'),
 ambiguous:scenario('https://members.netmarble.com','/auth/signin/email',true)};
process.stdout.write(JSON.stringify(result));
'''
        result = subprocess.run(['node', '-e', fixture], input=json.dumps(source), text=True,
                                capture_output=True, check=True, timeout=10)
        data = json.loads(result.stdout)
        self.assertEqual(data['form'], dict(first='filled', second='submitted', clicks=1,
                                          events=['input', 'input'], filled=True))
        self.assertEqual((data['select']['first'], data['select']['second'], data['select']['clicks']),
                         ('opened_email', 'waiting', 1))
        for key in ('wrongOrigin', 'signup', 'ambiguous'):
            self.assertEqual(data[key], dict(first='waiting', second='waiting', clicks=0, events=[], filled=False))


if __name__ == '__main__': unittest.main()
