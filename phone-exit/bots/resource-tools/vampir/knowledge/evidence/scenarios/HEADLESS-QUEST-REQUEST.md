# Запрос списка квестов ID 1801

22 октября 2026. Продолжение [полного ответа ID 1802](HEADLESS-QUEST-LIST.md).
EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.

## Wire и native-проверка

Точное имя PktQuestListRead связывает таблицу `0x149966f30`, getter
`0x145835640` → 1801, writer `0x145700e20` и mirror reader `0x14582ca50`.
Полный constructor `0x145829aa0` устанавливает эту таблицу и обнуляет
byte +0x10 / qword +0x18. Это исходные поля объекта, не доказательство
допустимых параметров запроса в текущем игровом состоянии.

Тело — ровно 9 байт, без native padding:

| Wire offset | Формат | Native field |
| --- | --- | --- |
| 0 | uint8 | packet+0x10 |
| 1 | uint64 little-endian | packet+0x18 |

Output table `0x149672748`: writer вызывает +0xe0 → `0x141c57110` →
virtual +0x70 → byte writer `0x144aadc60`; затем +0xb8 → `0x142108430` →
virtual +0x48 → uint64 writer `0x144aade10`. Общий raw append +0x88 —
`0x144aadd50`. Mirror reader сохраняет qword без изменения, байт ограничивает
значением 12. Writer, в отличие от reader, сохраняет байты 13 / 127 / 255.
Это различие не означает, что сервер принимает такие значения.

`replay-release-quest-request.py` исполняет целые constructor / ID getter /
writer / mirror reader, реальные scalar methods и virtual aliases.
Raw append заменён ограниченным fixture: только ширины 1 / 8 и память
текущего replay. Проверены 32 сочетания, включая uint64 0 / 1 / high bit /
maximum, два отказа writer и девять коротких префиксов reader без overread.
Лёгкий encoder `quest_request.encode_quest_list_read` совпал с native bytes.
Encoder проверяет текущий SHA и точные целочисленные диапазоны, не отправляет
кадров и не задаёт неизвестные значения автоматически.

## Поиск вызова: границы вывода

Прямые E8-вызовы constructor и LEA на packet table не дали проверенных
callers. Найден E9-кандидат `0x1457630a0`, отнесённый к chained root
`0x14575ee40`; полное декодирование фрагмента этим инструментом не завершилось.
Он не считается доказанным producer, границы не угадывались.

По непосредственному значению 1801 найдена `0x14649b840`. В конце проверенных
инструкций она вызывает virtual +0xa0: RCX — локальный context, EDX — 1801,
R8D — локальное вычисленное значение. Полный экспорт показывает только один
параметр context и работу с локальными коллекциями; входящего packet parameter
не найдено. Это не установленный handler ID 1802 и не доказанный sender ID 1801.
Назначение virtual +0xa0 отдельно неизвестно.

Нужно восстановить producer / lifecycle запроса, смысл qword +0x18 и
корреляцию ответа. Подставлять QuestInfoId из таблицы или считать qword
курсором пагинации по его ширине нельзя. В этом этапе вход, ID 1801 и выбор
квеста не выполнялись.

## Версии enum и защита инструмента

Enum EQuestType новой сборки сохранён отдельно, по SHA: Scenario 0, Sub 1,
Daily 2, Dungeon 3, Conquest 4, Bloodline 5, GuildDungeon 6, Guide 7,
Wanted 8, GuildDefense 9, GuildDefenseSudden 10, Item 11, Max 12.
Эти имена описывают enum descriptor; соответствие raw10 конкретному полю
должно опираться на producer / setter, одного совпадения clamp 12 недостаточно.

Старый extractor не разбирал аргументы: вызов с `--help` выполнял обычное
извлечение и перезаписывал общий внешний `native-enums.json`. Полученный
current результат сохранён отдельно; исторические значения восстановлены
из snapshot старого SHA. Исторический источник не переносился в факты новой
сборки. Теперь argparse обрабатывает справку до чтения / записи артефактов.
Повторный `--help` проверен: SHA внешнего файла до / после одинаковый.

## Материалы и воспроизведение

Внешняя библиотека `F:/PhoneExit Resources/Vampir/`:

- Discovery: `code-clues/release-world-packet-discovery/680f94e8029d9c347f865d7586a2f0f515e6e7ae084a56d5168eb12695b57a12/manifest.json`.
- Native replay: `code-clues/release-quest-request-replay/493385a64324f0dd165229366800012bff534ac3bb5ea6bcaeeb4db1fc7f07cc/manifest.json`.
- Current enum: `code-clues/release-native-enums/a924941605ff74d28a8442c216eb273be5697bcab060e95bb51553f042fad024/manifest.json`.

SHA256 этих manifest равны именам каталогов. Публичные данные, без auth captures.
Ghidra comparison `c7552efd2125-98802d550890/run-fd4956a37b3c/`:

- Writer / reader: `details/run-a1a98a73de63/details.json`, SHA256
  `0e30af15e3ff4bebf44bb7f6f4a44b8fa77cf19941c937516bd028f951b0e04e`.
- Context function: `details/run-f9080c6990ba/details.json`, SHA256
  `1c99cafdcb9a965ed6083377bc5fa03e8994cf17cfb51c1a0410e089cf510749`.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_request.py
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-release-ping-result.py --packet PktQuestListRead
python -X utf8 phone-exit/bots/resource-tools/vampir/extract-native-enums.py --help
```

Следом — источник параметров и установленный receiver ответа. После этого
связать явный диагностический запрос с полным bounded ID 1802 в одной сессии.
