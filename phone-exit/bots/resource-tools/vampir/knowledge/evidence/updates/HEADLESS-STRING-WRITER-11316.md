# Полный string writer 1.13.16 с native UTF-8

Источник — EXE 1.13.16, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [изолированных UTF-8 helpers](HEADLESS-UTF8-11316.md).
Общий writer `0x144aad310` исполнен целиком вместе с length `0x14144c550`,
converter `0x1414465f0` и bounded encoder `0x14143f320..0x14143f45c`.
Готовые экспорты использованы повторно, Ghidra не запускалась.

[Контекст](../../native-contexts/string-writer-11316.json) закрепляет SHA exports,
байты encoder и явные fixture bindings. [Проверка](../../../verify-string-writer-context.py)
сверяет прямые вызовы writer, косвенный archive slot `+0x28` и замкнутость
переходов encoder. Разрешённые native инструкции берутся из EXE того же SHA.
Allocator / free, memcpy, security cookie check и archive method моделируются
ограниченными fixtures. Неизвестный исполняемый адрес отклоняется harness.

## Результат и границы

228 сценариев проверили пустую строку, ASCII, кириллицу, CJK, emoji,
повреждённые суррогаты, noncharacters, встроенный NUL и длины до 4095 UTF-8 байт.
Полный writer передаёт archive fixture реальные преобразованные bytes и
корректный std::string descriptor / terminator. Он сканирует первый UTF-16 NUL,
а положительный FString count использует как условие ветви: count 1 при более
длинном terminated storage не ограничивает сканирование одним unit.
Для count 0 проверен null pointer: writer использует собственную пустую строку.

Подтверждены следующие границы:

- 15 байт помещаются в inline std::string; с 16 используется allocation fixture.
- 127 UTF-8 байт плюс terminator помещаются в промежуточный стековый буфер;
  128 байт требуют отдельного UTF-8 allocation. Он освобождается до archive call.
- Для 4095 байт исполняется ветвь выравнивания std::string: запрос 4135 байт,
  сохранение исходного указателя и освобождение исходного allocation.
- Archive return byte 0 / 1 / 128 / 255 возвращается без bool normalization.
  Верхние биты fixture return не попадают в итоговый результат.
- Даже при archive return 0 все созданные буферы освобождаются. Проверены размер
  и указатель free, canaries, неизменность входа / descriptor / archive, семь
  nonvolatile registers, RSP и прохождение security epilogue.

Это конечные fixtures валидного terminated storage. Ненулевой count с null
pointer, произвольные размеры / указатели и allocation failure не проверяются.
Фактический OS allocator, free и security implementation не исполняются.
Archive fixture проверяет полученную строку и возвращает заданный byte;
**native archive encoding, uint16 length и raw IO здесь ещё не доказаны**.
Game Version / Login preparation и result readers также не исполнялись.
Runtime profile, baseline, авторизация и игровые действия не менялись.

[Квитанция machine report](STRING-WRITER-11316.json). Сам отчёт хранится вне Git.
Отдельный прогон занял около 5 секунд на текущем ПК; три acceptance tests —
9,985 секунды. Это время данной проверки, не всей цепочки обновления.
Тесты также отклоняют повреждённый export / leaf, неверный SHA, archive slot
и подменённый free target.

## Повтор и следующий патч

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-string-writer-context.py --context phone-exit/bots/resource-tools/vampir/knowledge/native-contexts/string-writer-11316.json
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_string_writer_context.py
```

`native-string-writer-context` зарегистрирован как offline / on_update check
для обоих игровых контрактов. Кэш учитывает context, exports, инструменты и
закреплённые runtime distributions. Новый SHA требует переноса проверки;
результат текущего SHA автоматически не становится доказательством нового.
Ориентир `native-string-writer-current` в
[release-update-targets](../../release-update-targets.json) указывает путь
поиска кандидата через writer calls / archive slot и запрещает автоматическое
продвижение runtime. Coverage игрового профиля остаётся partial.

Следующий этап — определить текущие archive implementations для string slot
`+0x28`, uint16 length и raw IO; исполнить их отдельно, затем соединить с уже
проверенным writer. Не повторять Ghidra exports этого writer / UTF-8 helpers.
