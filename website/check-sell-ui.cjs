const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
(async()=>{
 const html=await (await fetch('http://127.0.0.1:8787/sell/')).text();
 const ids=new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]));
 const i18n=html.match(/<script id="i18n-data" type="application\/json">(.*?)<\/script>/s)[1];
 const node=()=>({hidden:false,textContent:'',value:'',dataset:{},classList:{remove(){},add(){},toggle(){}},setAttribute(){},removeAttribute(){},addEventListener(){},querySelector:()=>node(),querySelectorAll:()=>[],contains:()=>false});
 const elements={};for(const id of ids)elements[id]=node();
 elements['i18n-data'].textContent=i18n;elements['order-form'].elements={amount:node(),region:node()};
 const document={documentElement:{},querySelector(selector){if(selector.startsWith('#'))return elements[selector.slice(1)]||null;return node();},querySelectorAll:()=>[],addEventListener(){}};
 const context={document,window:{matchMedia:()=>({matches:true})},ResizeObserver:class{observe(){}},Intl,location:{protocol:'http:'}};
 vm.createContext(context);vm.runInContext(fs.readFileSync(__dirname+'/dist/app.js','utf8'),context);
 assert.equal(document.documentElement.lang,'en');
 console.log('Shared storefront JavaScript initializes on seller page without retail calculator or official-link elements: OK');
})().catch(error=>{console.error(error);process.exitCode=1});
