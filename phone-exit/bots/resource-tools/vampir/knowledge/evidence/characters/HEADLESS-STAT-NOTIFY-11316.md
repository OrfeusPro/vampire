# Начальные stats и изменения характеристик 1.13.16

Source SHA256 EXE:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [primitive replay](HEADLESS-STAT-VALUES-11316.md).

## Текущий контракт

Сетевые ID 321 / 322 связаны с readers `1456c4740` / `1456c5630`.
ID 322: entity key Q, count LE u16, записи `(I32, Q, Q)`, bool, u16.
ID 321 содержит тот же ключ и массив без трёх последних байт.
Запись — native stride 32: stat type `+8`, два raw64 поля `+10` / `+18`.
Reader `1457a8030`, callback `1456c6690`, ctor leaf `1457a3310`.
Применяется второе поле; значение первого не названо дельтой или прежним значением.

Начальный `PktCharacter` reader `145787640` вызывает `145734dd0` для массива
`main+1c8`. Callback `14573d240` создаёт `PktStat`: stride 24, type `+8`, value
`+10`; reader `1457a7f70`, ctor leaf `1457a32d0`, table `149921c20`.
Apply `145d8b8d0` передаёт значение в тот же setter, что delta apply `145d8b830`.
`1455f0130` записывает его в модель по stat type. Для CombatPower / type 134
есть отдельное деление signed значения на 100 с усечением к нулю.

Реестр 208 имён EStat извлечён из текущих descriptor pairs. Небольшой runtime
реестр генерирует `build-stat-names-11316.py` из закреплённого отчёта
`6e78d5ed9523d64e3e771da24da6b9fd2f95fd78c8d308076717918d369d205a`.
Level / Hp / MaxHp / Mp / MaxMp — 3 / 4 / 5 / 9 / 10; это source bindings,
не подбор названий по величине. Runtime `stats.value` сохраняет raw signed64
как десятичную строку, включая type 134; единицы модификаторов не угаданы.

## Native проверки и fixtures

- `replay-stat-notify-11316.py`: 1119 сценариев полного ID 321 / 322 reader,
  current archive, vector, ctor / callback / record, apply и existing-key setter
  на одной памяти. Полные / короткие тела, bool 0 / 255, повторы, коллизии map,
  signed значения и type 134. Для небольших массивов — все префиксы;
  для 207 записей — восемь выбранных границ на каждый вид пакета.
- `replay-stat-initial-11316.py`: 203 сценария начального массива и применения
  в модель, включая 207 записей. Ссылка `main+1c8 → 145734dd0` проверяется
  по текущим инструкциям; весь `PktCharacter` reader здесь не исполняется.
- Прежние 130 primitive-сценариев сохранены отдельно.

Allocation / reset, временный cleanup, memcpy, ownership wrapper и внешний
identity service — fixtures. Existing-key setter исполняется с 207 заранее
выделенными ключами и hash collisions. Вставка в map, listeners, реальный engine
и визуальные эффекты level-up не доказаны. Инструкционный лимит whole read —
300000; fixture capacity — 256 записей. Portable decoder строже native по trailing
bytes. Профиль не получает разрешений на отправку игровых команд.

Immutable отчёты в библиотеке ресурсов:

- `code-clues/stat-notify-11316/cc4d6d693cfa81813a4c941d9379542fb9a3750df3b41347865dc052f915a508/manifest.json`.
- `code-clues/stat-initial-11316/07a682971e1dcee11548ed02207f42ba79c7ec4b9d79ce546752dfb232dbf819/manifest.json`.

SHA256 каждого отчёта равен имени каталога. Состав и полные SHA Ghidra exports /
leaf bytes закреплены в `knowledge/native-contexts/stat-notify-11316.json`
и `stat-initial-11316.json`. Collect задания с `1457a3310` был отклонён из-за
отсутствия unwind; 27-байтный leaf до RET проверен отдельно, затем исключён
из новых Ghidra roots. Искусственная unwind-граница не добавлялась.

## Runtime

Источник сессии привязывается один раз. ID 321 / 322 принимаются только для
текущего полного SHA и ключа выбранного персонажа. Начальные stats не затирают
более поздние уведомления из того же receive batch. Повторные типы применяются
в порядке массива; данные разных аккаунтов не разделяют модель.
При ошибке чтения параметры сбрасываются в неизвестные, после close очищаются.
Лимиты — 65536 байт на notify, 1024 элемента / сохранённых stat types.
HP / MP и уровень выводятся только для неотрицательных безопасных целых JS;
полные signed64 значения сохраняются строками в `character.stats`.

Live-проверка и визуальное подключение компонентов описаны отдельно в
[результате проверки](HEADLESS-LIVE-STATS-CHECK-11316.md).
