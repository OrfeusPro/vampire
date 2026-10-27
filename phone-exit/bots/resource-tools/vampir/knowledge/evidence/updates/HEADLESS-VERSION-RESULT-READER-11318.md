# VersionResult 1.13.18: reader и общий input archive

EXE SHA256 `d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Продолжение [Version prepare](HEADLESS-VERSION-BATCH-11318.md).
Профиль и авторизация не запускались.

## Общий пакет и происхождение

Фиксированный набор 15 roots: reader `1456DC9C0`, input constructor
`144AACE40`, buffer constructor `144AAC430`, u16/u32/time/u64/bool/raw,
string/std-string и четыре UTF-8 helpers. Кандидаты проверены через полные
instruction/control shapes, реальные call/RIP links, constructor tables и
архивные slots. Смещение само по себе не является доказательством роли.
`align-version-result-11318.py` воспроизводит этот перенос, отклоняя изменение
формы или неоднозначность. Alignment result не объявляется semantic proof.

Один collect получил все 15 roots:
`run-ed5c8eee70bc/details.json`, SHA256
`8463fef01f722fccfca821d50b57824135019a75ef0794e192bdd3ab12d7ae3f`.
Полные инструкции сверяются с EXE; включена проверка whole ranges, blocks,
direct flow и conditional fallthroughs. Packet constructor `1456D8070`, ID
getter и три archive leaves закреплены отдельными bytes/SHA; leaf не выдаётся
за unwind root. Packet table `149928568` связывает reader в slot+20 и ID 2
в slot+28; имя PktVersionResult сверяется в adjacent literal.

Input base table нового SHA `149671EE8`; shared buffer fixture допускает
её только для данного полного SHA. Историческая table `1496706E8` сохраняется
только для 1.13.16. Неверная table или неизвестный SHA отклоняются. Остальные
contexts и факты старого SHA не заменены.

## Native проверка

- 32 полных тела: code 0/1/58/max × flag 0/1/2/255 × два poison fills;
- 17 коротких тел и 5 отказов каждой archive operation: reader останавливается;
- дополнительное тело с хвостом: native reader потребляет 17 байт, portable
  exact-size policy остаётся строже;
- 72 варианта native buffer construction: два constructors, размеры 0/1/4096,
  mode 0/1/max, endian 0/1, два poison fills.

Проверены field projection через portable VersionResult decoder, consumption,
ABI и canaries. Итого 127 случаев. Пять unittest тестов прошли, включая
старые регрессии, неправильную source-specific table и фиксированный root set
alignment. Тесты не используют сеть и не активируют профиль.
Подробный native отчёт в библиотеке ресурсов:
`knowledge/native-version-result-checks/164c9cf28e5e16bc167b2dd5e84a5cdee29e944253501697e6843a706b5d350f/manifest.json`.

## Что ещё неизвестно

Handler candidate `14679D680` по реальным вызовам ведёт в gate `1467CDC80`
и tail Login prepare `1467CE500`. Это пока только навигация. У gate текущий
unwind range `1467CDC80..1467CE18B` содержит inline switch data после RET
`1467CE096`. Линейный декодер прекращает разбор на этой таблице; полное
доказательство gate требует code/data separation и проверки switch targets.
В этой работе gate не экспортирован и его проверка не закрыта.

Reader и input archive могут использоваться для следующих result packets,
но не подтверждают их поля, handlers или registration. Вызовы allocation,
string storage/copy, free/security остаются fixtures; реальных network bytes,
SDK session, server acceptance и reader→handler composition нет.

## Автоматизация

`native-version-result-context` получил новый SHA, source context, pinned
exports и полные tool dependencies; `on_update` сохранён. Context переносится
повторяемым инструментом, а native replay проверяет результат отдельно.
Reviewed reader binding добавлен в Version contract и update target.
Старые результаты не переобъявлены совместимыми с новым SHA.
