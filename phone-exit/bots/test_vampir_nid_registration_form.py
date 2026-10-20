import json
from pathlib import Path
import subprocess
import unittest


class RegistrationFormTests(unittest.TestCase):
    def test_observed_forms_do_not_resubmit_or_expose_values(self):
        source = (Path(__file__).parent / 'vampir-headless/windows/nid-register.js').read_text('utf-8')
        fixture = r'''
const vm=require('node:vm');
const source=JSON.parse(require('node:fs').readFileSync(0,'utf8'));
class Input {
 constructor(type,placeholder='') {Object.assign(this,{tagName:'INPUT',type,placeholder,disabled:false,saved:'',checked:false,textContent:'',children:[]});}
 get value(){return this.saved;} set value(value){this.saved=value;}
 getClientRects(){return [{}];} dispatchEvent(){} click(){this.checked=!this.checked;}
}
function button(text){return {tagName:'BUTTON',textContent:text,disabled:false,children:[],clicks:0,
 getClientRects(){return [{}];},click(){this.clicks++;}};}
let controls=[],body='',path='/auth/signup/terms';
const location={origin:'https://members.netmarble.com',get pathname(){return path;}};
const document={body:{get innerText(){return body;}},querySelectorAll(selector){
 if(selector==='button,a,input,[role="button"]')return controls;
 if(selector==='a,button,span,div')return [];
 throw Error('Unexpected selector');}};
const run=vm.runInNewContext(source,{location,document,HTMLInputElement:Input,Event:class{}});
const input={email:'fixture@vampir.top',password:'fixture-secret',code:'',state:{}};
function step(){input.state=run(input);return input.state;}
const required=['[Required]Agree to Terms of Service','[Required]Agree to Privacy Policy'];
const boxes=required.concat('[Optional]Marketing Consent').map(text=>{
 const box=new Input('checkbox');box.parentElement={textContent:text,querySelectorAll(){return [box];},parentElement:null};return box;});
const agree=button('Agree');controls=boxes.concat(agree);boxes[2].checked=true;step();step();step();step();
if(!boxes[0].checked||!boxes[1].checked||boxes[2].checked||agree.clicks!==1)throw Error('terms');
path='/auth/signup/email/input';const mail=new Input('text','Enter email'),send=button('Send verification email');controls=[mail,send];
step();step();step();if(send.clicks!==1||mail.value!==input.email)throw Error('email retry');
path='/auth/signup/email/verify';const code=new Input('text','Enter only numbers.'),verify=button('Confirm Verification Code');controls=[code,verify];
if(!step().need_code)throw Error('missing code request');input.code='12345';step();step();step();
if(verify.clicks!==1||code.value!=='12345')throw Error('verify retry');
path='/auth/signup/password/input';const p1=new Input('password'),p2=new Input('password'),next=button('Next');controls=[p1,p2,next];
step();step();step();if(next.clicks!==1||p1.value!==input.password||p2.value!==input.password)throw Error('password retry');
body='Account Registration Complete';if(!step().complete)throw Error('completion');
if(JSON.stringify(input.state).includes(input.password)||JSON.stringify(input.state).includes(input.code))throw Error('secret state');
location.origin='https://unrelated.invalid';if(run(input)!==null)throw Error('origin');
location.origin='https://members.netmarble.com:444';if(run(input)!==null)throw Error('port');
location.origin='https://members.netmarble.com';path='/auth/signup/email/input';body='Verification emails can only be sent once every 3 minutes.';
input.state={email_sent:true};if(step().stopped!=='mail_rate_limited'||send.clicks!==1)throw Error('rate limit');
process.stdout.write('ok');
'''
        result = subprocess.run(['node', '-e', fixture], input=json.dumps(source), text=True,
            capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'ok')


if __name__ == '__main__': unittest.main()
