# Текущие defaults пресета: constructor и граница CDO

EXE SHA256 `03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Для продолжения Viper перенесён малый пакет трёх whole constructors:
`0x1454d5020` (preset), `0x143b5ef20` (DataAsset), `0x1417cbdc0` (UObject).
Готовый `run-ddd300a85f1d` использован без нового Ghidra при проверке.

24 сочетания трёх poison-памятей, двух feature states, наличия / отсутствия
class и уже привязанного / пустого initializer плюс null object подтверждают:
семь float получают 0.5, VoiceType — 0. Девять integer полей сохраняют poison.
Проверены vtable, границы объекта, запись initializer и условный class service.
Initializer lookup, UObject service и class service остаются fixtures; ветка
неправильного initializer не допускается. Native allocation / completion /
CDO property-copy и загрузка конкретного asset не исполнены.

Descriptor bytes, ASCII names, flags и offsets проверяются по текущему EXE:
17 полей пресета, включая VoiceType `+0x70`. Это source-bound поля, а не
доказательство текущего engine cache / полного registration lifecycle.

Для Viper это закрывает текущие constructor float / voice defaults, но не
позволяет автоматически заполнить отсутствующие integer поля нулями. В
[извлечённых F / M assets](HEADLESS-CREATE-VIPER-RESOURCES.md) явные значения
сохраняются поверх defaults; полный текущий allocation / CDO / consumer и
Create 103 / Result 104 остаются необходимыми для runtime factory.

Субагент также собрал, но не успел исполнить ClassInfo / selection roots:
`0x1454ceec0`, `0x1458962b0`, `0x145896980`, `0x1458b6800`,
`0x14642cf80`, `0x14644bfa0` в `run-49796294d192`; lookup `0x145895b40`
и iterator `0x14142e750` готовы отдельно. Навигационные материалы сохранены в
`F:/PhoneExit Resources/Vampir/knowledge/viper-current-*.json`.
Их наличие не превращается в semantic / runtime допуск; повторный экспорт не нужен.

Check `preset-defaults-current` включён в `on_update`, отдельную tooling-группу
и `MODULES`. Он сохраняет точный source / context / exports и границы native
стенда. На другом SHA старые адреса не применяются автоматически.
