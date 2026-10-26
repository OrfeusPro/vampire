# SightEnter: композиция полного wire-пакета

Источник — EXE 1.13.16, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Внешний reader `1456c5390`, экспорт `run-f4d4115c1822`, проверен по имеющемуся
псевдокоду и instruction anchors. [Контракт](HEADLESS-SIGHT-ENTER-CONTRACT-11316.md)
фиксирует descriptor / callback / constructor / vtable для пяти массивов.
Этот этап добавляет композицию portable reader; целое native исполнение внешних
callbacks с copy / cleanup ещё не выполнено. Runtime ID 301 не включён.

## Разбор

`sight_enter_event.decode_sight_enter` использует общий `CurrentRecordReader`:

| Native offset | Wire |
| --- | --- |
| +10 | u16 count + CharacterOther records |
| +20 | u16 count + NpcCreateData records без notify flag |
| +30 | u16 count + GroundEffectData records |
| +40 | u16 count + Gadget records |
| +50 | bool presence; при наличии u16 count + ProjectileCircleData records |
| +70 | u16 count + TetherEffectData records |
| +80 | byte, ограниченный 32 |

Native offsets не используются как wire sizes. Фиксированные тела ground / tether /
projectile circle имеют ранее проверенные wire lengths 50 / 66 / 65 bytes.
Их интерпретируют существующие декодеры. Gadget boundary scanner читает 48 bytes
фиксированного prefix, u16 count и uint64 keys, optional owner со строкой, tail byte;
значения интерпретирует существующий whole Gadget decoder. CharacterOther и NPC
читаются общими уже проверенными методами, без сброса бюджета между записями.

Бюджет 0–4096, default 1024, списывается за каждую запись всех внешних массивов,
вложений и map, включая duplicate entries. Для Gadget keys он списывается до
передачи выделенного тела существующему decoder. Все проверки источника, immutable
bytes, 64 KiB, UTF8 / text policy и точного конца тела сохранены. Optional absent
остаётся `None`, present-empty — `()`. Результат — immutable записи с offsets;
семантика игрока, actor, HP или координат мира по этим offsets не назначается.

## Проверка

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sight_enter_11316.py
```

Четыре теста: source-bound static контракт; mixed пакет со всеми типами и
Unicode owner, высокими uint64 и повторными keys / projectiles; точный общий
бюджет 17 против недостаточного 16; все обрезанные префиксы этого пакета;
все 256 tail bytes; absent / empty projectile optional; source / размер / input /
trailing guards; чрезмерные counts каждого внешнего массива и projectile optional;
две последовательные записи с одним недостаточным бюджетом. Независимые результаты
с разными keys не изменяют друг друга. Это не проверка двух сетевых сессий.

Статический тест повторяет SHA / instructions / descriptor / virtual reader checks
существующего инструмента `inspect-sight-enter-11316.py`. Нового Ghidra-экспорта нет.
Component native replays CharacterOther / NPC create повторно проходят после
расширения общего cursor; это regression proof компонентов, не whole SightEnter.

## Следующее обязательное действие

Исполнить настоящий внешний reader вместе с outer callbacks, native copy / cleanup,
input и вложениями на mixed arrays, truncation и границах count. Callback CharacterOther
`1456c5e60` читает временную stack запись, копирует через `1456bedd0` и очищает
через `145785200`. Компонентный replay напрямую в final object этого не проверял.
Нужны проверенные source-bound copy / cleanup и владение string / array / map.
Затем установить handler → actor / world и подключить initial entities к сессиям.
До этих проверок новый decoder остаётся вне live обработки; coverage окружения
сохраняется partial. Новый вход в игру и живой multi-account тест не выполнялись.
