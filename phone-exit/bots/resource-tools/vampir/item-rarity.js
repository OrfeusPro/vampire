(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.ItemRarity = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  // 100/101 are special categories, not grades above Mythic. 102 is ERarity::Max.
  const order = new Map(['5', '4', '3', '2', '1', '0', '100', '101'].map((id, index) => [id, index]));
  function rank(item) { return order.get(String(item?.rarity?.id ?? item?.data?.Rarity)) ?? order.size; }
  function compare(a, b) { return rank(a) - rank(b); }
  return { rank, compare };
});
