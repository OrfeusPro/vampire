/* Shared view components: explicit input state and callbacks, no transport/subscriptions/timers. */
(function(root) {
  'use strict';
  function create({ el, append, image, portrait, button, icon, fmt, vitals, geometry, definitions, schemas }) {
    const spec = definitions.modules.player_status;
    const compiled = VampirLayoutSchema.solve(schemas.player_status, { root: spec.frame_root,
      frame: geometry.rect(0, 0, spec.frame.width, spec.frame.height), targets: spec.layout_targets, policy: spec.layout_policy });
    if (Object.keys(compiled.unknowns).length) throw Error('Не разобрана геометрия общего статуса: ' + JSON.stringify(compiled.unknowns));
    const boxes = compiled.rects;
    function playerStatus({ state, character, onOpen }) {
      const view = VampirWidgetRenderer.mount({ document, schema: schemas.player_status,
        options: { root: spec.frame_root, frame: geometry.rect(0, 0, spec.frame.width, spec.frame.height), policy: spec.layout_policy },
        bindings: spec.render_bindings, actions: { 'open-character': onOpen } });
      const node = view.node; node.classList.add('player-status'); node.dataset.component = 'player-status'; node.dataset.sourceResource = spec.resource; node.dataset.geometryState = 'allocated-component-frame';
      node.dataset.layoutEngine = 'projected-widget-tree'; node.dataset.layoutAssumptions = JSON.stringify(view.compiled.assumptions);
      const avatar = view.elements.portrait_button;
      let appearanceKey;
      for (const id of ['hp', 'mp']) view.elements[id].dataset.vital = id;
      function update(next, person) {
        avatar.setAttribute('aria-label', 'Открыть персонажа ' + (person?.name || 'Демо')); avatar.title = person?.name || 'Персонаж';
        const nextAppearance = JSON.stringify(person?.appearance || null);
        if (appearanceKey !== nextAppearance) {
          const picture = portrait(person?.appearance); picture.style.setProperty('--portrait-x', String(boxes.portrait.x - boxes.portrait_button.x)); picture.style.setProperty('--portrait-y', String(boxes.portrait.y - boxes.portrait_button.y)); picture.style.setProperty('--portrait-size', String(boxes.portrait.width));
          avatar.replaceChildren(picture); appearanceKey = nextAppearance;
        }
        const values = {};
        for (const value of vitals(next)) { values[value.id] = { value: value.value, max: value.max }; values[value.id + '_text'] = String(value.value) + '/' + String(value.max); }
        view.update(values);
      }
      update(state, character); return { node, update, dispose: view.dispose };
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
      update(state, character); return { node, update, dispose: status.dispose };
    }
    function mainMenu({ onSelect }) {
      const definition = definitions.modules.main_menu;
      const node = el('nav', undefined, 'source-main-menu');
      node.setAttribute('aria-label', 'Разделы игры'); node.dataset.component = 'main-menu';
      node.dataset.sourceResource = definition.resource;
      node.dataset.appearanceState = definition.status;
      definition.groups.forEach((entries, index) => {
        const group = el('div', undefined, index === definition.groups.length - 1 ? 'source-menu-footer' : 'source-menu-group');
        for (const entry of entries) {
          const item = icon('/Game/RED/UI/Resource/Texture/Image/' + entry.icon, entry.label, () => onSelect(entry));
          item.dataset.sourceControl = entry.control;
          item.dataset.brushBinding = 'package-reference-candidate';
          group.append(item);
        }
        node.append(group);
      });
      return node;
    }
    return { playerStatus, titleBar, currency, wallets, mainMenu };
  }
  root.VampirUiComponents = { create };
})(typeof globalThis !== 'undefined' ? globalThis : this);
