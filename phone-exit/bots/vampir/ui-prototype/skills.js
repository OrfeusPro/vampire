/* Curated historical skill IDs; Russian labels and all rules below are demo-only. */
(function(root) {
  'use strict';
  const groups = {
    SwordMan: [['140011','Кровавый удар'],['140012','Кровавая баня'],['140014','Кровавая ярость']],
    Gunner: [['130011','Разоружение'],['130012','Дикий выстрел'],['130013','Проклятие']],
    Fighter: [['150014','Поглощающее касание'],['150015','Кровавый разрез'],['150016','Удар хаоса']],
    DarkMage: [['110016','Водоворот'],['110017','Ядовитый взрыв'],['110018','Болото страданий']],
    Reaper: [['120011','Смертельный удар'],['120012','Тёмные оковы'],['120013','Проникновение тени']]
  };
  const skills = Object.fromEntries(Object.entries(groups).flatMap(([classId, rows]) => rows.map(([id, name], i) => [id, { id, name, classId, mp: 40 * (i + 1), cooldown: 3000 * (i + 1), learnCost: 500, maxLevel: 3 }])));
  const forClass = classId => Object.values(skills).filter(s => s.classId === classId);
  const initial = classId => {
    const rows = forClass(classId);
    return { levels: Object.fromEntries(rows.slice(0, 2).map(s => [s.id, 1])), slots: [rows[0].id, rows[1].id, null, null, null], auto: [], readyAt: {} };
  };
  function validate(value, classId) {
    if (!value || !value.levels || typeof value.levels !== 'object' || Array.isArray(value.levels) || !Array.isArray(value.slots) || value.slots.length !== 5 || !Array.isArray(value.auto) || !value.readyAt || typeof value.readyAt !== 'object' || Array.isArray(value.readyAt)) return false;
    const learned = id => Object.hasOwn(skills, id) && skills[id].classId === classId && Object.hasOwn(value.levels, id);
    if (Object.entries(value.levels).some(([id, n]) => !learned(id) || !Number.isInteger(n) || n < 1 || n > skills[id].maxLevel)) return false;
    if (value.slots.some(id => id !== null && !learned(id)) || new Set(value.slots.filter(Boolean)).size !== value.slots.filter(Boolean).length) return false;
    return new Set(value.auto).size === value.auto.length && value.auto.every(learned) && Object.entries(value.readyAt).every(([id, until]) => learned(id) && Number.isSafeInteger(until) && until >= 0 && until <= 1e15);
  }
  const api = { skills, forClass, initial, validate };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.VampirSkills = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
