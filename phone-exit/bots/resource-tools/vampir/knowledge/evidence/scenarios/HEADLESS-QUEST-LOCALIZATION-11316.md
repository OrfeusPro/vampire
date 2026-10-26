# Русские этапы: native применение Untranslated / fallback / префикса

Source EXE 1.13.16:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Prepare request:
`eb3fc7c4e856663f8a25f54796771dfd4dd59b9d8f1d2aae29975ff230d61909`.
Целый transformation `14585e070` взят из run-b89911c14f11 с SHA
`cf4ca1a14258dfa7d85b14a8bbe376fae7a57010b7c2d5bf895c2e855f0c1316`;
block/direct-flow coverage полные. Новая Ghidra collection не нужна.
Russian QuestTask_Name SHA:
`88efc2a29c7a52a4148ef916689b77044b25b4c028ad4feea96d0b4782ee57b7`.

## Исполненные решения

Whole native function принимает std::string descriptor, FString output и
fallback descriptor, а также byte Untranslated пятым аргументом. Settings getter
`14563dd10` даёт flags +1E4/+1E5. Названия flags неизвестны; ниже они обозначены
offsets, без догадки о продуктовых настройках. Native result pointer равен output.

Проверены 336 сценариев: шесть исходных русских названий «Зова крови» и восемь
lexical strings × две комбинации каждого settings flag × Untranslated 0/1 ×
пустой/непустой fallback × inline/external SSO, когда длина UTF-8 допускает inline.
Для source Russian labels получается 96 случаев, для lexical — 240.
Каждый запуск повторно сверяет именованные current PAK данные через
[source-bound inspector](HEADLESS-QUEST-OVERRIDE-DATA-11316.md), а не доверяет
старому каталогу. Русский presentation locale сохраняется явно выбранным.

Исполняются следующие ветви:

- При flag+1E4=0 и Untranslated!=0 output становится пустым.
- При flag+1E4!=0, Untranslated!=0, пустом переводе и непустом fallback вызывается
  fallback helper. Выбор делает native код; сам helper остаётся fixture.
- При flag+1E5=0 native проверяет первые три UTF-16 units; префикс `###`
  приводит к пустому output. При flag+1E5!=0 эта проверка пропускается.
- Иначе возвращается исходный перевод с передачей строкового descriptor.

Проверены пустая строка, короткая кириллица, `###`, `###Нет перевода`, обычный
текст, внутренний `###`, ASCII и astral Unicode. Source labels при
Untranslated=0 сохраняют «Идите ко входу», «Подойдите к связанному», «Преследуйте
врага» во всех проверенных комбинациях flags. Input descriptors / bytes / flags
не меняются, output guards сохранены, все временные fixture allocations
освобождены. Returned output/fallback storage освобождается после сверки.

## Fixtures и ограничения

Native исполняет ветвления, чтение flags, передачу ownership и cleanup call flow.
UTF8→wide wrapper, FString copy/storage, prefix extraction, compare, fallback
construction, settings getter, free и security cookie — bounded fixtures.
Последний сохраняет RAX. Prefix literal `14996c9c0` проверен как exact UTF-16
`###\0`. Settings flags явно синтетические, не данные текущего процесса.

Пустая FString в fixtures имеет count=0; реальные альтернативные empty storage
representations здесь не заявлены. Аллокатор успешен, UTF-8 вход ограничен 255
байтами, wide scan — 512 units. Преобразование Unicode/allocator не исполнены
native, проверены native решения при их явно заданных результатах.

Whole override loader `145b69ca0`, missing/duplicate ID handling, active flags,
file/header/current service policy и whole catalog ещё не проверены совместно.
Это не proof отображения этих шагов у живого персонажа и не выбор active index.
`order_admitted=false`; игровая сессия и owner не меняются.

## Воспроизведение

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_localization_11316.py
```

`replay-quest-localization-11316.py`, контекст
`knowledge/native-contexts/quest-localization-11316.json`, offline check
`native-quest-localization-11316`. Артефакт в библиотеке ресурсов:
`code-clues/quest-localization-11316/f683ea086d46667ae8d9cee176c0c61a2fef8a93b9830bc579e3a78e69491ad6/manifest.json`.

Далее — выполнить ru override loader с этим transformation, explicit flags,
missing/duplicate rows, затем перейти к whole catalog. Runtime не допускается
на основании одного bounded replay; живые команды не отправляются.
