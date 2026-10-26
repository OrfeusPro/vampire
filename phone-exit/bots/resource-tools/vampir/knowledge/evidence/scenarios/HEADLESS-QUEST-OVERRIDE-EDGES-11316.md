# Русские overrides: duplicate / unmatched / missing translation

Source EXE:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Prepare request:
`4c0bea907cb9e8d4a0ddf7627419a81669ebd17ccc6833a93688ed3e6f32f4ef`.
Использованы прежние pinned exports; новая collection не нужна.

Сценарий расширяет [совместную native load chain](HEADLESS-QUEST-LOADER-OVERRIDE-11316.md),
а не заменяет её Python merge. Исполняются base/ru loaders, tokenizer, scalar
getters, record/map chain, localization transform, lookup и group construction.

## Исходные строки

Current PAK SHA:
`15cf4f880170e87fc5fdea661cf9ba3d54a4f66c607844f5ab1047ed87f1e6a4`.
Основной QuestTask entry 2983, SHA
`6f2eec83a42c722caca8b6d4e7d7ff0768b2873fcf40cbd476fd843ce4689a2a`.
Русский entry 2359, SHA
`88efc2a29c7a52a4148ef916689b77044b25b4c028ad4feea96d0b4782ee57b7`.
Source bytes извлекаются из current PAK с прежними SHA/reader/Oodle checks.

К шести задачам «Зова крови» добавлены настоящие base records `60000070024`
(нет русского перевода) и `50000090011` (две русские строки). Читаются исходные
физические строки без CSV writer: 1841 main bytes и 663 ru bytes на запуск.
Девятая ru строка — `110110010`, которой нет среди выбранных восьми main rows.
В полном каталоге этот ID существует: **unmatched относится к тестовому
подмножеству**, а не к отсутствию задания в игре.

## Native результаты

- Две source ru строки `50000090011` содержат `2026-05-12 Registered` и
  `2026-06-16 Registered`, обе с Untranslated=TaskName. В прямом порядке output
  равен June text; в обратном — May text. Native lookup возвращает ту же запись,
  затем выполняется повторное assignment: последнее прочитанное значение
  побеждает при явно выбранных flags и string services этого сценария.
- `110110010` проходит native lookup, который не находит запись, и путь
  diagnostic/count. Новая primary запись не появляется: до/после 8 records,
  3 groups. Diagnostic fixture только считает вызов, не пишет runtime logs.
- Main record `60000070024` не встречается в ru потоке; его TaskName остаётся
  исходной пустой FString. Param и остальные main fields сохранены.
- Все 8 TaskName assignments (6 обычных + 2 duplicate) проходят native transform.
  В обоих порядках сохраняются original Param, scalar/flag/position fields и
  group pointer insertion order. После загрузки проверены все heap guards.

Native Untranslated handling дважды вызывает split/compare path, проверяет
TaskName среди заданных частей и передаёт флаг в transform. В обоих запусках
по 8 reads Untranslated / assignments, 2 splits, 1 missing-ID diagnostic,
19 header lookups; actual CRT calls 64 atoi / 33 _atoi64 / 16 strtoul / 32 pow.

## Ограничения

Settings flags +1E4/+1E5 явно равны 1, чтобы native не скрывал source
Untranslated labels. Это исследовательская комбинация, не утверждение о
настройках пользователя или живого клиента. При иных flags поведение
Untranslated отличается, как показано в
[336 transform cases](HEADLESS-QUEST-LOCALIZATION-11316.md).

File/header, named Untranslated read, split/destruction/compare, UTF/string
storage/assignment, allocation/map clear/bit/hash/duplicate check и diagnostics
остаются bounded fixtures. Lookup `L10NRegistrationDate` возвращает empty cell
явно: fallback/date formatting не проверяется; непустой source TaskName не
использует этот fallback. Native сравнение/ветвление по ID/колонкам/flags и
порядок assignments исполняются, native string implementation — нет.

Выбранные service-group fields пусты, current nonzero policy не вызывается.
Нет whole 5944/8461-row load, actual file/header lookup, active locale/settings,
allocation failure или live runtime admission. `order_admitted=false`.
Проверка одного actual duplicate ID не доказывает совпадение всех 48 groups;
candidate presentation catalog пока сохраняет неоднозначности отдельно.

## Воспроизведение

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_override_edges_11316.py
```

Общий `replay-quest-loader-11316.py` теперь выбирает строки по explicit task IDs
и проверяет несколько groups. Прежние шесть-строчные режимы остаются checks.
Контекст `knowledge/native-contexts/quest-override-edges-11316.json`, offline
check `native-quest-override-edges-11316`. Артефакт:
`code-clues/quest-override-edges-11316/d34218399a252917d7232fdbe68e36574d15f34a98f390c15b389fc11df90345/manifest.json`.

Далее whole catalog / actual file-header / current policy перед active-step
admission. Действующая сессия и owner не перезапускались, команд в игру нет.
