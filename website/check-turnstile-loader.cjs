const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(__dirname+'/dist/app.js','utf8');
const loader=source.slice(source.indexOf('function loadTurnstile(){'),source.indexOf('async function prepareTurnstile(){'));
const prepare=source.slice(source.indexOf('async function prepareTurnstile(){'),source.indexOf('function resetTurnstile(){'));
async function test(){
 const scripts=[];let timers=[],renders=0,resets=0;
 const context={window:{},turnstileLoader:null,turnstileWidget:null,turnstileSize:null,dialog:{open:true},securityContainer:{clientWidth:400,dataset:{sitekey:'public'}},securityStatus:{},securityNotice(){},document:{createElement:()=>({remove(){this.removed=true}}),head:{append(script){assert.equal(typeof context.window.vampirTurnstileLoaded,'function');scripts.push(script)}}},setTimeout:f=>(timers.push(f),timers.length),clearTimeout(){}};
 vm.createContext(context);vm.runInContext(loader+prepare,context);
 const first=context.prepareTurnstile();assert.equal(scripts.length,1);assert.match(scripts[0].src,/onload=vampirTurnstileLoaded/);
 context.window.turnstile={render(){renders++;return 'widget'},reset(){resets++},ready(){throw new Error('ready must not be called')}};
 context.window.vampirTurnstileLoaded();await first;assert.equal(renders,1);
 await context.prepareTurnstile();assert.equal(renders,1);assert.equal(resets,1);
 delete context.window.turnstile;context.turnstileLoader=null;
 const failed=context.loadTurnstile();scripts[1].onerror();await assert.rejects(failed);assert.equal(context.turnstileLoader,null);
 const retry=context.loadTurnstile();assert.equal(scripts.length,3);context.window.turnstile={render(){}};context.window.vampirTurnstileLoaded();await retry;
 assert(!source.includes('turnstile.ready('));console.log('Turnstile loader: callback registered before async script, render/reset, network failure and retry OK');
}
test().catch(e=>{console.error(e);process.exitCode=1});
