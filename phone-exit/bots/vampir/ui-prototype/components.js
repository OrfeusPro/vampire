/* Shared view components: explicit input state and callbacks, no transport/subscriptions/timers. */
(function(root) {
  'use strict';
  function create({ el, append, image, portrait, button, icon, fmt, vitals, geometry, definitions, schemas }) {
    const spec = definitions.modules.player_status;
    const compiled = VampirLayoutSchema.solve(schemas.player_status, { root: spec.frame_root,
      frame: geometry.rect(0, 0, spec.frame.width, spec.frame.height), targets: spec.layout_targets, policy: spec.layout_policy });
    if (Object.keys(compiled.unknowns).length) throw Error('Не разобрана геометрия общего статуса: ' + JSON.stringify(compiled.unknowns));
    const boxes = compiled.rects;
    function position(node, box) {
      Object.assign(node.style, { position: 'absolute', left: `calc(${box.x} * var(--ui-component-unit))`, top: `calc(${box.y} * var(--ui-component-unit))`, width: `calc(${box.width} * var(--ui-component-unit))`, height: `calc(${box.height} * var(--ui-component-unit))` });
      return node;
    }
    function playerStatus({ state, character, onOpen }) {
      const node = el('div', undefined, 'player-status'); node.dataset.component = 'player-status'; node.dataset.sourceResource = spec.resource; node.dataset.geometryState = 'allocated-component-frame';
      node.dataset.layoutEngine = 'local-widget-schema'; node.dataset.layoutAssumptions = JSON.stringify(compiled.assumptions);
      const avatar = position(button('', onOpen, 'player-status-portrait'), boxes.portrait_button);
      let appearanceKey;
      node.append(avatar);
      const views = new Map();
      for (const id of ['hp', 'mp']) {
        const bar = position(el('div', undefined, 'vital-bar ' + id), boxes[id]);
        bar.dataset.vital = id; bar.setAttribute('role', 'progressbar'); bar.setAttribute('aria-label', id.toUpperCase()); bar.setAttribute('aria-valuemin', '0');
        const fill = el('div', undefined, 'vital-fill'), text = el('span', undefined, 'vital-value'); append(bar, fill, text); node.append(bar); views.set(id, { bar, fill, text });
      }
      function update(next, person) {
        avatar.setAttribute('aria-label', 'Открыть персонажа ' + (person?.name || 'Демо')); avatar.title = person?.name || 'Персонаж';
        const nextAppearance = JSON.stringify(person?.appearance || null);
        if (appearanceKey !== nextAppearance) {
          const picture = portrait(person?.appearance); picture.style.setProperty('--portrait-x', String(boxes.portrait.x - boxes.portrait_button.x)); picture.style.setProperty('--portrait-y', String(boxes.portrait.y - boxes.portrait_button.y)); picture.style.setProperty('--portrait-size', String(boxes.portrait.width));
          avatar.replaceChildren(picture); appearanceKey = nextAppearance;
        }
        for (const value of vitals(next)) {
          const view = views.get(value.id), label = String(value.value) + '/' + String(value.max);
          view.fill.style.width = value.ratio * 100 + '%'; view.text.textContent = label;
          view.bar.setAttribute('aria-valuenow', String(value.value)); view.bar.setAttribute('aria-valuemax', String(value.max)); view.bar.setAttribute('aria-valuetext', label);
        }
      }
      update(state, character); return { node, update };
    }
    function currency(key, value) {
      const node = el('span', undefined, 'currency'); node.setAttribute('aria-label', (key === 'gold' ? 'Золото: ' : 'Алмазы: ') + fmt(value));
      return append(node, image(key === 'gold' ? 'IMG_Asset_Gold' : 'IMG_Asset_Diamond'), el('span', fmt(value)));
    }
    function wallets(state) { return append(el('div', undefined, 'currencies'), currency('gold', state.gold), currency('diamonds', state.diamonds)); }
    function titleBar({ heading, state, character, onMenu, onClose, onCharacter }) {
      const node = el('header', undefined, 'game-titlebar'); node.dataset.component = 'game-titlebar'; node.dataset.sourceResource = definitions.modules.title_bar.resource;
      const status = playerStatus({ state, character, onOpen: onCharacter }), balance = el('div', undefined, 'game-header-wallets'), tools = el('div', undefined, 'game-header-tools');
      const menu = icon('IMG_Flat_Menu', 'Меню', onMenu), close = icon('IMG_Flat_Exit', 'Закрыть ' + heading.textContent, onClose);
      close.dataset.windowClose = 'true'; menu.classList.add('game-header-menu'); close.classList.add('game-header-exit');
      append(tools, heading, menu, close); append(node, status.node, balance, tools);
      let balanceKey;
      function update(next, person) { status.update(next, person); const key = next.gold + ':' + next.diamonds; if (key !== balanceKey) { balance.replaceChildren(wallets(next)); balanceKey = key; } }
      update(state, character); return { node, update };
    }
    return { playerStatus, titleBar, currency, wallets };
  }
  root.VampirUiComponents = { create };
})(typeof globalThis !== 'undefined' ? globalThis : this);
