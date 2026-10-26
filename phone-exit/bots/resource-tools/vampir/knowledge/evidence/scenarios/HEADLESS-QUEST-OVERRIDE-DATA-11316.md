# QuestTask overrides: текущие русские строки и native связи

Для отображения выбран русский язык по явному запросу пользователя. Это выбор
presentation locale, а не утверждение о языке сетевой сессии или engine globals.

Source EXE:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Current PAK:
`15cf4f880170e87fc5fdea661cf9ba3d54a4f66c607844f5ab1047ed87f1e6a4`.
Prepare request `05d7b414f157cf2b389cdfb73b83feca88ec31cf965b4769600ebc211755a72f`
показал отсутствующий материал. У getter `145a4dc20` нет unwind root, поэтому
новый explicit request `f0b7c042ecb8a270cf2c2a41567acef54ca939538e28524cbf1d6c20b1b6cd56`
содержит только настоящие roots. Collection run-b89911c14f11 экспортировала
`14585e070`, SHA
`cf4ca1a14258dfa7d85b14a8bbe376fae7a57010b7c2d5bf895c2e855f0c1316`.
Override `145b69ca0` уже был в run-bc83e3fb45a2, SHA
`9b45aee958178e4bb551632a6dc60db2867ba88168d0e177345cee75e200e3dd`.

## Связи native-кода

Файл из literal `1499f7b78` — `QuestTask_Name.csv`; колонки — Id, TaskName,
необязательный Param. Код override ищет существующую primary запись по ID.
Store TaskName проходит через `14585e070` и строковое присваивание в record+78;
Param имеет отдельную такую цепочку в record+90. Проверены exact instructions
этих двух destination offsets и ветка сравнения Param column index с -1,
которая пропускает его update. Это static source binding, не native execution.

Getter `145a4dc20` exact bytes `488d052921ba05c3` возвращает адрес descriptor
`14b5efd50`. Текущее значение языка этого descriptor не считывалось из
живого процесса и не заменяется предположением JP/HK → locale.
Transformation `14585e070` также читает language flags +1E4/+1E5, обрабатывает
Untranslated / пустую строку / fallback-prefix. Эти ветви ещё нужно выполнить
до допуска whole override. Сам export не доказывает активные flags.

## Именованные данные текущего PAK

Authoritative directory manifest:
`resource-config-snapshots/d2691f91f8d88d15329639bc8457bced595cef0d5ee6b4bfff3b17e98c97f523/manifest.json`.
Проверены полный SHA PAK, manifest, directory.json, encoded-entries.bin, record
index, decoder/Oodle и decoded bytes. Native basename сопоставлен с именами
directory с учётом регистра; это не доказательство фактического file lookup
или приоритета loose files в работающем клиенте.

Найдены все 16 локалей. Во всех QuestTask_Name CSV колонки одинаковы:
Id, TaskName, L10NOrder, L10NRegistrationDate, Untranslated. **Param отсутствует**.
На штатном column lookup это означает -1 и пропуск native Param update;
сам header lookup в данном исследовании не исполнялся.

Русский `CSV/L10N/ru/QuestTask_Name.csv`: entry 2359, offset 16726016, SHA
`88efc2a29c7a52a4148ef916689b77044b25b4c028ad4feea96d0b4782ee57b7`.
8461 строка, 8413 уникальных ID. Из 5944 основных задач 5943 ID имеют русские
строки; отсутствует `60000070024`. Есть 2470 дополнительных уникальных ID и
48 повторных строк (48 повторяющихся ID). Вне Git сохранены 5895 однозначных
названий, все 48 групп повторов с ordinal и один missing ID. Победитель среди
повторов не выбирается; runtime admission false.
Корейская таблица содержит 5944 строки и совпадает по ID с base без повторов;
это не меняет выбранный пользователем русский язык. Остальные 15 локалей имеют
такое же количество строк / matched / missing / duplicate ID, как русская.

| ID этапа «Зова крови» | Русский TaskName |
| --- | --- |
| 110120005 | Идите ко входу |
| 110120010 | Идите ко входу |
| 110120020 | Идите ко входу |
| 110120030 | Подойдите к связанному |
| 110120040 | Подойдите к связанному |
| 110120070 | Преследуйте врага |

Название этапа не выбирает активный index и не доказывает NPC actor / маршрут.
Строки дополняют [основной loader](HEADLESS-QUEST-LOADER-11316.md); полная
native override execution / duplicate application order / missing-key handling
и file/header/current service policy остаются следующим шагом.

## Воспроизведение и границы

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_override_data_11316.py
```

Инструмент `inspect-quest-override-data-11316.py`, контекст
`knowledge/native-contexts/quest-override-data-11316.json`, registered offline
check `quest-override-data-11316`. Артефакт:
`code-clues/quest-override-data-11316/4191c44efe9ed73df863d84327802b18ba416ad21281c683bb578b56eb7e44c8/manifest.json`.

Это static/data inspection, native_execution=false, order_admitted=false.
Игра, owner, UI snapshot и настройки не изменялись; живые команды не посылались.
