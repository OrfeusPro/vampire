'use strict';
const {messages, languages: availableLanguages, defaultLanguage, currentLanguage, pricing} = JSON.parse(document.querySelector('#i18n-data').textContent);
let language = defaultLanguage;
const selector = document.querySelector('#language');
const dialog = document.querySelector('#order-dialog');
const form = document.querySelector('#order-form');
const result = document.querySelector('#order-result');
let savedRequest = null;
let savedEmailAccepted = true;
let orderSubmitting = false;
let turnstileWidget = null;
let turnstileLoader = null;
let turnstileSize = null;
const securityContainer = document.querySelector('#order-turnstile');
const securityStatus = document.querySelector('#turnstile-status');
function securityNotice(){securityStatus.textContent=messages[language].securityCheck;}
function loadTurnstile(){
  if(window.turnstile)return Promise.resolve();
  if(turnstileLoader)return turnstileLoader;
  turnstileLoader=new Promise((resolve,reject)=>{
    const script=document.createElement('script');
    script.src='https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
    script.async=true;script.defer=true;
    const timer=setTimeout(()=>reject(new Error('security unavailable')),15000);
    script.onload=()=>{clearTimeout(timer);window.turnstile?window.turnstile.ready(resolve):reject(new Error('security unavailable'));};
    script.onerror=()=>{clearTimeout(timer);reject(new Error('security unavailable'));};
    document.head.append(script);
  });
  return turnstileLoader;
}
async function prepareTurnstile(){
  try{
    await loadTurnstile();
    if(!dialog.open)return;
    if(turnstileWidget!==null){window.turnstile.reset(turnstileWidget);return;}
    turnstileSize=securityContainer.clientWidth<300?'compact':'flexible';
    turnstileWidget=window.turnstile.render(securityContainer,{
      sitekey:securityContainer.dataset.sitekey,action:'order',theme:'dark',size:turnstileSize,language:'auto',
      callback:()=>{securityStatus.textContent='';},
      'error-callback':()=>{securityNotice();return true;},
      'expired-callback':()=>{securityNotice();},
      'timeout-callback':()=>{securityNotice();}
    });
  }catch{securityNotice();}
}
function resetTurnstile(){
  if(turnstileWidget!==null && window.turnstile)window.turnstile.reset(turnstileWidget);
}
new ResizeObserver(()=>{
  if(!dialog.open || orderSubmitting || turnstileWidget===null)return;
  const size=securityContainer.clientWidth<300?'compact':'flexible';
  if(size!==turnstileSize){window.turnstile.remove(turnstileWidget);turnstileWidget=null;prepareTurnstile();}
}).observe(securityContainer);
function translate(lang) {
  language = messages[lang] ? lang : defaultLanguage;
  selector.querySelector('.language-current').textContent = availableLanguages.find(item=>item.code===language).label;
  document.querySelectorAll('[data-language]').forEach(link=>{if(link.dataset.language===language)link.setAttribute('aria-current','page');else link.removeAttribute('aria-current');});
  document.documentElement.lang = language;
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el=>el.placeholder=messages[language][el.dataset.i18nPlaceholder]);
  document.querySelectorAll('[data-i18n-aria]').forEach(el => el.setAttribute('aria-label', messages[language][el.dataset.i18nAria]));
  document.querySelectorAll('[data-i18n]').forEach(el => { const value=messages[language][el.dataset.i18n]; if(value!==undefined) el.textContent=value; });
  document.querySelectorAll('[data-i18n-html]').forEach(el => { const value=messages[language][el.dataset.i18nHtml]; if(value!==undefined) el.innerHTML=value; });
  document.title = messages[language].pageTitle;
  document.querySelector('meta[name="description"]').content = messages[language].metaDescription;
  document.querySelector('#official-link').href=`https://vampirgb.netmarble.com/${language==='ru'?'ru':'en'}/preorder`;
  if(savedRequest) result.textContent=messages[language][savedEmailAccepted?'success':'notificationWarning'].replace('{id}',savedRequest);
  updatePrices();
}
const languageMenu=document.querySelector('#language-menu');
languageMenu.addEventListener('click',event=>{
 const link=event.target.closest('a[data-language]');
 if(!link || !availableLanguages.some(entry=>entry.code===link.dataset.language))return;
 document.cookie=`vampir_language=${encodeURIComponent(link.dataset.language)}; Path=/; Max-Age=31536000; SameSite=Lax${location.protocol==='https:'?'; Secure':''}`;
});
function closeLanguageMenu(restoreFocus=false){languageMenu.hidden=true;selector.setAttribute('aria-expanded','false');if(restoreFocus)selector.focus();}
function openLanguageMenu(){languageMenu.hidden=false;selector.setAttribute('aria-expanded','true');}
selector.addEventListener('click',()=>{if(languageMenu.hidden)openLanguageMenu();else closeLanguageMenu();});
selector.addEventListener('keydown',event=>{if(event.key==='ArrowDown'||event.key==='ArrowUp'){event.preventDefault();openLanguageMenu();const options=languageMenu.querySelectorAll('a');options[event.key==='ArrowDown'?0:options.length-1].focus();}});
languageMenu.addEventListener('keydown',event=>{
 const options=[...languageMenu.querySelectorAll('a')],index=options.indexOf(document.activeElement);
 if(['ArrowDown','ArrowUp','Home','End'].includes(event.key)){event.preventDefault();const next=event.key==='Home'?0:event.key==='End'?options.length-1:(index+(event.key==='ArrowDown'?1:-1)+options.length)%options.length;options[next].focus();}
});
document.addEventListener('click',event=>{if(!event.target.closest('.language'))closeLanguageMenu();});
document.addEventListener('keydown',event=>{if(event.key==='Escape'&&!languageMenu.hidden){event.preventDefault();closeLanguageMenu(true);}});
document.querySelector('.language').addEventListener('focusout',event=>{if(!event.currentTarget.contains(event.relatedTarget))closeLanguageMenu();});
translate(currentLanguage || defaultLanguage);
document.querySelectorAll('.select-package').forEach(button=>button.addEventListener('click',()=>{
  if(orderSubmitting)return;
  const customAmount = document.querySelector('#custom-amount');
  if(button.hasAttribute('data-custom') && !customAmount.reportValidity()) return;
  form.reset();savedRequest=null;result.textContent='';form.elements.amount.value=button.hasAttribute('data-custom') ? customAmount.value : (button.dataset.amount || customAmount.value || '1000');
  updatePrices();
  dialog.showModal();form.elements.amount.focus();securityStatus.textContent='';prepareTurnstile();
}));
document.querySelector('.close-dialog').addEventListener('click',()=>dialog.close());
dialog.addEventListener('click',e=>{if(e.target===dialog){const r=dialog.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)dialog.close();}});
form.addEventListener('submit',async e=>{
  e.preventDefault(); if(!form.elements.region.value){regionTrigger.setAttribute('aria-invalid','true');regionTrigger.focus();openRegion();return;} if(!form.reportValidity())return;
  if(orderSubmitting)return;
  const token=turnstileWidget!==null && window.turnstile ? window.turnstile.getResponse(turnstileWidget) : '';
  if(!token || window.turnstile.isExpired(turnstileWidget)){securityNotice();securityContainer.focus();return;}
  orderSubmitting=true;
  const submit=document.querySelector('#submit-order');submit.disabled=true;submit.textContent=messages[language].sending;result.textContent='';
  try {
    const payload=Object.fromEntries(new FormData(form));payload.language=language;payload['cf-turnstile-response']=token;
    const response=await fetch('/api/order.php',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':document.querySelector('meta[name="csrf-token"]').content},body:JSON.stringify(payload)});
    const data=await response.json();if(!response.ok||!data.id)throw new Error(data.error||'request failed');
    savedRequest=data.id;savedEmailAccepted=data.email_accepted===true;result.textContent=messages[language][savedEmailAccepted?'success':'notificationWarning'].replace('{id}',data.id);form.reset();updatePrices();
  } catch(error){result.textContent=error.message.startsWith('turnstile_')?messages[language].securityCheck:messages[language].error;}
  finally{resetTurnstile();orderSubmitting=false;submit.disabled=false;submit.textContent=messages[language].submit;}
});

const amountInput = document.querySelector('#custom-amount');
function syncAmounts(){
  updatePrices();
  document.querySelector('[data-adjust="-1000"]').disabled=Number(amountInput.value)<=1000;
  document.querySelectorAll('[data-preset]').forEach(button=>{
    const selected=Number(amountInput.value)===Number(button.dataset.preset);
    button.classList.toggle('active',selected); button.setAttribute('aria-pressed',String(selected));
  });
}
document.querySelectorAll('[data-preset]').forEach(button=>button.addEventListener('click',()=>{
  amountInput.value=button.dataset.preset; syncAmounts();
}));
document.querySelectorAll('[data-adjust]').forEach(button=>button.addEventListener('click',()=>{
  const current=Number(amountInput.value)||0;
  amountInput.value=Math.min(10000000,Math.max(1000,current+Number(button.dataset.adjust)));syncAmounts();
}));
amountInput.addEventListener('input',syncAmounts);
syncAmounts();

const menuToggle=document.querySelector('.menu-toggle');
const siteHeader=document.querySelector('.header');
function closeMenu(){siteHeader.classList.remove('menu-open');menuToggle.setAttribute('aria-expanded','false');}
menuToggle.addEventListener('click',()=>{const open=siteHeader.classList.toggle('menu-open');menuToggle.setAttribute('aria-expanded',String(open));});
document.querySelectorAll('#primary-nav a').forEach(link=>link.addEventListener('click',closeMenu));
document.addEventListener('keydown',event=>{if(event.key==='Escape')closeMenu();});
document.addEventListener('click',event=>{if(!siteHeader.contains(event.target))closeMenu();});

function updatePrices(){
  for(const [inputSelector, outputSelector] of [['#custom-amount','#price-total'],['#order-form [name="amount"]','#order-price-total']]){
    const input=document.querySelector(inputSelector),output=document.querySelector(outputSelector);
    if(!input||!output)continue;
    const amount=Number(input.value);
    output.textContent=Number.isInteger(amount)&&amount>=1000&&amount<=10000000
      ? new Intl.NumberFormat(language,{minimumFractionDigits:2,maximumFractionDigits:5}).format(amount*pricing.rateCents/100000)+' USD'
      : '— USD';
  }
}
form.elements.amount.addEventListener('input',updatePrices);
updatePrices();

const regionTrigger=document.querySelector('#region-trigger');
const regionOptions=document.querySelector('#region-options');
function closeRegion(){regionOptions.hidden=true;regionTrigger.setAttribute('aria-expanded','false');}
function openRegion(){regionOptions.hidden=false;regionTrigger.setAttribute('aria-expanded','true');}
function resetRegion(){form.elements.region.value='';document.querySelector('#region-value').textContent='—';regionTrigger.removeAttribute('aria-invalid');regionOptions.querySelectorAll('[data-region]').forEach(option=>option.setAttribute('aria-selected','false'));closeRegion();}
regionTrigger.addEventListener('click',()=>regionOptions.hidden?openRegion():closeRegion());
regionOptions.querySelectorAll('[data-region]').forEach(option=>option.addEventListener('click',()=>{form.elements.region.value=option.dataset.region;document.querySelector('#region-value').textContent=option.firstChild.textContent;regionOptions.querySelectorAll('[data-region]').forEach(item=>item.setAttribute('aria-selected',String(item===option)));regionTrigger.removeAttribute('aria-invalid');closeRegion();regionTrigger.focus();}));
regionTrigger.addEventListener('keydown',event=>{if(['ArrowDown','ArrowUp'].includes(event.key)){event.preventDefault();openRegion();const options=regionOptions.querySelectorAll('[data-region]');options[event.key==='ArrowDown'?0:options.length-1].focus();}});
regionOptions.addEventListener('keydown',event=>{const options=[...regionOptions.querySelectorAll('[data-region]')],index=options.indexOf(document.activeElement);if(['ArrowDown','ArrowUp','Home','End'].includes(event.key)){event.preventDefault();options[event.key==='Home'?0:event.key==='End'?options.length-1:(index+(event.key==='ArrowDown'?1:-1)+options.length)%options.length].focus();}});
document.addEventListener('click',event=>{if(!event.target.closest('.region-field'))closeRegion();});
document.querySelector('.region-field').addEventListener('focusout',event=>{if(!event.currentTarget.contains(event.relatedTarget))closeRegion();});
dialog.addEventListener('cancel',event=>{if(!regionOptions.hidden){event.preventDefault();closeRegion();regionTrigger.focus();}});
form.addEventListener('reset',resetRegion);
dialog.addEventListener('close',closeRegion);
