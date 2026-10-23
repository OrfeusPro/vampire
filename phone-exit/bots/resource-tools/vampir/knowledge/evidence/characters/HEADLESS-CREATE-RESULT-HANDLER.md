# Ответ создания ID 104: целый handler и решение runtime

23 октября 2026. EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [JSON внешности](HEADLESS-CREATE-APPEARANCE-JSON-KEYS.md) и
[чтения результата](HEADLESS-CREATE-RESULT-READER.md).

## Успех: запись принимается независимо от совпадения имени

Целая `0x146796690` исполнена в **128 успешных сценариях**: четыре пары имён,
selection state present / absent, UI valid / missing / mismatch / range,
feature off / absent / empty / active.

При code 0 handler сравнивает имя результата с сохранённым именем manager.
Совпадение вызывает дополнительный callback `0x145d5e430`.
Независимо от него manager получает запись `packet+0x18` через `0x145c98110`.
При наличии selection state ключ `packet+0x20` записывается в state `+0x400`.
Несовпадение имени не превращает code 0 в отказ и не вызывает повтор создания.

UI refresh выполняется только при найденном объекте и подходящей иерархии типа;
native вызов slot `+0x598` получает `(ui, 1, 1)`. Затем выполняется финальный
success callback `0x145d54870`. Feature callback `0x14563d790` вызывается при
включённом global flag, найденном feature object и непустом target `+0xa0`.
Проверены порядок captures, неизменность пакета и единственная разрешённая
запись в selection state; guards не изменены.

## Отказ: код и снятие ожидания

Проверены **30 ошибочных сценариев**: raw codes 1 / 59 / `0xffffffff`,
PlayerState present / absent, UI valid / missing / disabled / mismatch / range.
Во всех случаях code передан `0x145fd5370(code, 0)`; record manager и success
callbacks не вызываются. Если первый PlayerState lookup возвращает null,
handler заканчивает работу. При валидном UI byte `+0x378` становится 0.

Если первый lookup успешен, а повторный UI lookup невалиден, текущий native
handler присваивает null и доходит до записи `null+0x378`. Двенадцать таких
эмуляторных write faults сохранены как граница поведения. Это **не утверждение
о падении живой игры**: состояние синтетическое, в игре может действовать
инвариант наличия UI. Runtime бота это обращение воспроизводить не должен.

Числа 1 / 59 / `0xffffffff` здесь — входные коды fixtures, не установленный
код «ник занят». Ненулевой код не даёт оснований менять ник и повторять создание.

## Fixtures и переносимое решение

Manager / state / UI / feature lookup и все побочные действия заменены captures.
FString allocation / free и сравнение непустых имён — fixtures; length и
special-empty branches выполняются native. Case / locale semantics engine
comparator не устанавливаются. Manager insertion internals, сохранение аккаунта
и реальный UI не исполняются. Никаких игровых пакетов / авторизации / сети.

В [character_create_result.py](../../../../../vampir-shared/vampir_core/character_create_result.py)
добавлена чистая функция `character_creation_outcome` с явным source SHA:

- code != 0 → `rejected`, без key / name и без retry;
- code 0 с непустым name и ненулевым key → `created` с серверной identity;
- code 0 с отсутствующей identity → `needs_refresh`, без повторного создания.

Проверка identity — локальная политика перед сохранением, строже native handler.
Различие requested / returned name — отдельный диагностический bool; оно не
отменяет успех. `retry_allowed` всегда false, пока код занятого ника не доказан.
Функция не пишет в БД и не назначает slot сама; worker ещё не подключён к отправке.

Два теста проверяют native сценарии и runtime outcome: несовпадающее имя при
успехе, ошибки, отсутствие identity, другой SHA и некорректные входы.
Существующие три теста ID 104 reader также прошли.
Следом — подключение явного Carnage candidate, Latin JSON builder и этой функции
к одной живой попытке при принятом пустом списке. После неоднозначного разрыва
сначала читать список, а не повторять Create. Если персонаж существует, новый
не создаётся. Политика занятого ника остаётся отдельной проверкой.

## Воспроизведение и источники

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-character-create-handler.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_character_create_handler.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_character_create_result.py
```

[Native replay](../../../replay-release-character-create-handler.py), offline check
`release-character-create-handler`. Отчёты сохраняются в библиотеке ресурсов
`code-clues/release-character-create-handler/` с SHA имени каталога и зависимостями.

Полный экспорт:
`ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details/run-dbbbcb857839/details.json`,
SHA256 `e3438a98efdd8b403847bd3b68095abe4a8f7b666a24be1fc0c893e8d6432a11`.
