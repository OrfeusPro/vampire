# Полученное сообщение обучения в изолированной сессии 1.13.16

26 октября 2026. Текущий EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Повторно использован [исторический decoder](HEADLESS-TUTORIAL-UPDATE-READER.md).
Прежние checks полного сценария обучения относятся к SHA `98802d55…` и остаются
requires_port: разрешение отправлять tutorial / quest команды не переносилось.

## Текущая цепочка чтения

Packet-name scanner нашёл candidate table `149969ad8`. Затем два явных экспорта
Ghidra и инструкции текущего PE подтвердили следующие связи:

| Участок | Адрес |
| --- | --- |
| Constructor ID 9905 / vptr store | `14584bda0` |
| Packet reader / вложенный dispatch | `1456b70d0` |
| Getter → 9905 | `145855ec0`, явный leaf |
| Вложенный constructor | `1457fdba0`, явный leaf |
| Вложенная таблица / reader | `1499290e0` / `1457fdf10` |
| Descriptor / reserve / callback | `14995ffd0` / `1456ba3a0` / `1457fdfa0` |
| Таблица элемента / reader | `1499290a0` / `1457fde80` |

Тело по-прежнему содержит bool, uint16 count и count записей `<IIIB>`:
raw08, raw0c, raw10, state. Native reader ограничивает state значением 3;
ненулевой bool становится true. Размер тела — `3 + 13 * count` байт.
Consumer / значения полей и флага для текущего клиента не объявлены проверенными.

Source-bound context:
`knowledge/native-contexts/tutorial-update-11316.json`.
Он закрепляет полные SHA пяти текущих экспортов, leaf bytes и vtable bindings.
Новые экспорты: `run-edd5235c81bf` и `run-a096b2a0bf20` под текущим SHA;
input primitives повторно использованы из уже проверенных текущих экспортов.

`replay-tutorial-update-11316.py` исполняет целые packet / nested constructors,
getter, readers, native цикл массива и callback. 73 полных тела покрывают
flag 0 / 1 / 255, count 0 / 1 / 2 / 8 и дополнительный count 64,
state 0 / 1 / 2 / 3 / 4 / 255. Все 835 коротких префиксов максимального
разрешённого тела отклонены; cursor не выходит за ввод, guards сохранены.
Поля native записей сверены с portable decoder после полного чтения.

Отчёт вне Git:
`code-clues/tutorial-update-11316/15341c2917f9f38937a982ccf866dd79cc69ae814b69a8aaa0dd71dfc79d56a0/manifest.json`.
Fresh reserve и cleanup пустого прежнего контейнера — fixtures.
Повторное использование / рост и освобождение заполненного native контейнера,
application handler и локальный запуск задачи здесь не исполнены.

## Контракт владельца

`tutorial_update.py` принимает только два явно проверенных source SHA.
Текущий `LiveSession` читает ID 9905 с лимитами 64 записи / 835 байт.
В snapshot / HTTP поле `tutorial` содержит только последнее полученное сообщение:
`semantics=last_received_message`, `applied_to_local_task=false`, flag и records.
Это не полный серверный map и не активный локальный шаг. Пустой массив означает
пустое сообщение; он не доказывает отсутствие заданий.

Переданные socket owner значения character_key / world_id сохраняются отдельно
как контекст наблюдения; неизвестные остаются null. Поздний publish не дописывает
их задним числом. Данные до world finish можно наблюдать, но они не активируют
квестовое меню и не отправляют команду. При следующем сообщении сохраняется его
собственный контекст; применение флага как reset / delta не угадывается.

Coverage: not_verified / not_received / last_received_message / decode_error.
Ошибка очищает прежнее сообщение и увеличивает tutorial_decode_errors;
close очищает данные. Журнал содержит tutorial_received / tutorial_decode_error
и число записей, без raw body. Тела не пишутся на диск.

Проверены 50 synthetic owners с одинаковыми ключами и разными полями,
deep-copy snapshot, пустое сообщение, unknown source, decoder error, close,
uint64 identity без потери точности и HTTP. Максимальные страницы NPC / игроков
также проверяются вместе с 64 tutorial records, в пределах прежних 256 КиБ.
Прошли 32 локальных Python-теста (включая исторический reader regression)
и все 20 выбранных knowledge checks для live-world-state-11316.

## Живая граница и следующий шаг

Успешная [сессия с картой](../maps/HEADLESS-LIVE-MAP-11316.md) уже работала
до подключения нового decoder. Она получила один ID 9905; тело не сохранялось,
и задним числом восстановить его нельзя. Код действующего socket owner не
перезагружался. Новая интеграция пока проверена на synthetic данных; при следующем
разрешённом входе / запуске владельца нужно получить реальное сообщение.

Далее проверить current registration → application handler / отложенную очередь,
связь полей с Tutorial / TutorialStep и фактическое состояние персонажа уровня 1.
Старый tutorial ack и ID 1801 с reset полями не повторять по одному raw state.
