/* Shared view components: explicit input state and callbacks, no transport/subscriptions/timers. */
(function(root) {
  'use strict';
  function create({ el, append, image, portrait, button, icon, fmt, vitals, geometry, definitions, schemas, statusSkin }) {
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
      for (const [key, control] of [['hp_frame', 'Image_224'], ['mp_frame', 'Image']]) {
        const node = view.elements[key], brush = statusSkin.brushes[control];
        if (brush.export.sha256 !== schemas.player_status.nodes[String(brush.export.index)].source.sha256) throw Error('Brush рамки относится к другому источнику.');
        const texture = image(statusSkin.texture), [left, top, right, bottom] = brush.margin;
        if (!texture.src) throw Error('Не опубликована исходная текстура рамки HP / MP.');
        node.style.borderImageSource = 'url("' + texture.src + '")';
        node.style.borderImageSlice = [top, right, bottom, left].map(v => v * 100).join(' ') + ' fill';
        node.style.borderWidth = [top * brush.image_size[1], right * brush.image_size[0], bottom * brush.image_size[1], left * brush.image_size[0]].map(v => 'calc(' + v + ' * var(--ui-component-unit))').join(' ');
        node.dataset.brushBinding = 'explicit-image-brush-resource-object';
      }
      const portraitSpec = definitions.modules.player_portrait;
      const portraitView = VampirWidgetRenderer.mount({ document, schema: schemas.player_portrait,
        options: { root: portraitSpec.frame_root, frame: geometry.rect(0, 0, boxes.portrait_component.width, boxes.portrait_component.height), policy: portraitSpec.layout_policy },
        bindings: portraitSpec.render_bindings });
      for (const [key, control] of [['background', 'ImageBG'], ['portrait', 'ImagePortrait'], ['frame', 'ImageFrame']]) {
        const source = statusSkin.portrait_brushes[control];
        if (source.export.sha256 !== schemas.player_portrait.nodes[String(source.export.index)].source.sha256) throw Error('Портрет относится к другому источнику.');
        const art = image(source.asset_path, 'player-portrait-art');
        if (!art.src) throw Error('Не опубликован исходный ресурс портрета.');
        portraitView.elements[key].append(art);
      }
      view.elements.portrait_component.append(portraitView.node);
      node.dataset.portraitMode = 'static-source-deferred-resources';
      for (const id of ['hp', 'mp']) view.elements[id].dataset.vital = id;
      function update(next, person) {
        node.dataset.stateSource = 'demo';
        for (const id of ['hp', 'mp']) delete view.elements[id].dataset.liveValueKnown;
        avatar.setAttribute('aria-label', 'Открыть персонажа ' + (person?.name || 'Демо')); avatar.title = person?.name || 'Персонаж';
        const values = {};
        for (const value of vitals(next)) { values[value.id] = { value: value.value, max: value.max }; values[value.id + '_text'] = String(value.value) + '/' + String(value.max); }
        view.update(values);
      }
      function updateLive(snapshot) {
        if (!root.VampirLiveState) throw Error('Не загружен адаптер живого состояния.');
        const live = root.VampirLiveState.playerStatus(snapshot), values = {};
        node.dataset.stateSource = 'live';
        avatar.setAttribute('aria-label', live.name || 'Персонаж'); avatar.title = live.name || 'Персонаж';
        for (const vital of live.vitals) {
          values[vital.id] = { value: vital.known ? vital.value : 0, max: vital.known ? vital.max : 1 };
          values[vital.id + '_text'] = vital.known ? String(vital.value) + '/' + String(vital.max) : '—';
          view.elements[vital.id].dataset.liveValueKnown = String(vital.known);
        }
        view.update(values);
      }
      update(state, character); return { node, update, updateLive, dispose() { portraitView.dispose(); view.dispose(); } };
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
      update(state, character); return { node, update, updateLive: status.updateLive, dispose: status.dispose };
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
