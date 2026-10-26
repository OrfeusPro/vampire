const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(__dirname + '/map-bridge.js', 'utf8');
function harness() {
  const events = new Map(), pointers = new Map(), timers = [];
  const context2d = new Proxy({}, {get:() => () => {}});
  const controls = {worlds:{disabled:true}, labels:{checked:false}};
  const parent = {postMessage() {}};
  const view = {x:20,y:30,s:.001};
  const context = {URL,URLSearchParams,JSON,Math,Number,Set,
    location:{origin:'http://127.0.0.1:17946',search:''},
    frameElement:{src:'http://127.0.0.1:17946/map.html?mode=live&bot=one&session=session-one'},
    parent,view,scene:{},innerWidth:1200,innerHeight:800,
    types:new Set(['Area','NpcSpawn']),update(){},schedule(){},
    $:id=>controls[id],setTimeout:fn=>timers.push(fn),clearTimeout(){},
    addEventListener:(name,fn)=>events.set(name,fn),
    document:{hidden:false,body:{append(){}},createElement:()=>({dataset:{},getContext:()=>context2d}),
      getElementById:()=>({addEventListener:(name,fn)=>pointers.set(name,fn)})}};
  vm.runInNewContext(source,context);
  function state(position,world='10010',map='10',overrides={}) {
    events.get('message')({origin:context.location.origin,source:parent,data:{source:'vampir-live-prototype',bot_id:'one',session_id:'session-one',type:'state',
      payload:{position,world_id:world,map_id:map,labels:true,follow:false},...overrides}});
  }
  return {view,state,controls,pointers,tick(){timers.shift()();}};
}
const h=harness();
h.state({x:90000,y:150000});h.tick();
assert.deepEqual(h.view,{x:20,y:30,s:.001},'wait for atlas setup/fit');
h.controls.worlds.disabled=false;h.tick();
assert.equal(h.view.x,90000);assert.equal(h.view.y,150000);
assert.equal(h.view.s,800/65000,'entry zoom matches explicit atlas focus scale');
h.view.x=123;h.view.y=456;h.view.s=.04;
h.state({x:90010,y:150010});h.tick();
assert.deepEqual(h.view,{x:123,y:456,s:.04},'poll updates preserve manual navigation');
h.pointers.get('pointerdown')({clientX:100,clientY:100});
h.pointers.get('pointerup')({clientX:100,clientY:100});h.tick();
assert.deepEqual(h.view,{x:123,y:456,s:.04},'object clicks preserve viewport');
h.state({x:1,y:2},'10012','11',{session_id:'another-session'});h.tick();
assert.equal(h.view.x,123,'wrong session cannot move map');
h.state({x:800,y:900},'10012','11');h.tick();
assert.deepEqual(h.view,{x:800,y:900,s:.04},'new world centers once without reducing zoom');
h.state(null);h.tick();h.view.x=100;
h.state({x:810,y:910},'10012','11');h.tick();
assert.equal(h.view.x,810,'reconnection re-arms entry centering');
h.view.x=200;h.state({x:NaN,y:1});h.tick();assert.equal(h.view.x,200,'unknown position cannot invent a center');
console.log('Live map entry: readiness, one-shot center/zoom, manual navigation, identity/world changes and unknown position passed');
