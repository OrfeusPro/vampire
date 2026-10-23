# Создание в сессии: пустой список, одна отправка и неизвестный исход

23 октября 2026. Используются подтверждённые codecs текущего EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [handler ID 104](HEADLESS-CREATE-RESULT-HANDLER.md).

## Подключённый runtime lifecycle

`exchange_game_login` принимает необязательный явный `creation_payload`.
По умолчанию поведение входа не меняется. Создание требует текущего SHA,
`read_character_list=True` и отсутствия одновременного выбора персонажа.
`GameConnection.queue_character_create` дополнительно требует успешного Login
этого соединения и принятого пустого списка ID 102 в `LIST_AVAILABLE`.
Отказ Login, отказ списка и непустой список не разрешают отправку ID 103.

Новый `CharacterCreationFlow` владеет одной попыткой на соединении:

```text
waiting_entry → queued → sent → created / rejected / needs_refresh
                   ↓       ↓
                    unknown
```

Queue refusal — `not_queued`, попытка на этом соединении потреблена, sequence
и очередь при отказе не меняются. Полное тело валидируется до постановки кадра.
ID 103 проходит через общую очередь, её sequence и текущий XOR key; sender
сообщает completion именно этого immutable frame. Только после этого ID 104
может завершить попытку. Ранний / поздний / повторный ID 104 учитывается как
unmatched, не назначает персонажа и не запускает Create заново.
Transaction ID в этом протоколе не подтверждён: это одна outstanding операция
того же TCP-соединения, а не гарантия корреляции по серверному request ID.

Timeout, EOF, закрытие или некорректный ответ после постановки кадра дают
`unknown`. При timeout connection закрывается, включая частично отправленный
хвост общей очереди. Unknown требует следующего входа и чтения списка; попытка
не повторяется на этом соединении. Функция ничего не знает о постоянном журнале
аккаунтов: worker должен сохранять неопределённость до нового чтения списка.

При полном ответе используется `character_creation_outcome`: отказ не сохраняет
identity error-record; успех с key/name возвращает серверные значения; успех
без identity требует списка. После создания выбор в том же соединении пока
не разрешён: требуется свежий список на новом соединении.

Результат exchange содержит состояние, code, retry=false, refresh_required и
число unmatched. Key возвращается при подтверждённом успехе; имя — только при
явном `expose_character_labels`. Обычный диагностический вывод не получает
created name. Флаг refresh требуется также после created для нового списка.

## Явный кандидат Carnage

[character_creation_candidate.py](../../../../../vampir-shared/vampir_core/character_creation_candidate.py)
собирает только Carnage/F: class 3, scalar bytes
`[1, 8, 16, 9, 2, 2, 2, 9, 0, 0]`, voice 0, пустые items и raw flags 0/0.
Float-входы — текущий preset: Height / Shape 0.4, Chest 0.3, остальные 0.5.
JSON builder явно использует Latin profile и float32 округление.
Decal zeros остаются **явным выбором из модели**, не доказательством live asset.
Пользователь допускает произвольную внешность, но серверный допуск кандидата
ещё требует живой попытки. Остальные классы этим factory не поддерживаются.

## Проверено локальными сокетами

Шесть тестов проверили:

- кадр ID 103: CRC / key / sequence / body против encoder, частичный send;
- ранний ID 104 до full send и дубликат после terminal outcome;
- accepted empty list против existing / rejected list;
- queue budget refusal без изменения sequence, запрет повторной попытки;
- malformed body, поздний ответ, deadline и close → unknown;
- очистку частичного хвоста и закрытие socket при timeout;
- настоящую локальную socket-сессию ID 1 → 3 → 101 → 103 → ответ 104;
- серверные key/name, отказ 104, EOF и timeout без повторного ID 103;
- отсутствие ID 103 при существующем персонаже и при Login 59.

Cleanup-тест отдельно использует внутренний fixture accepted-list state;
он не выдаётся за настоящий Login. Полная socket-сессия выполняет реальный
локальный обмен framed bytes с synthetic version/login/list/record bodies.
Это интеграция runtime, **не native replay и не живая проверка сервера игры**.
Существующие 40 тестов exchange, 9 connection и 12 selection также прошли.

## Следующий этап

Подключить явный запуск из account worker, сохранять server key/name и журнал
неопределённого исхода до следующего принятого списка. Только после этого
выполнить разрешённую живую попытку для одного пустого EU-аккаунта.
Сейчас UI / worker отправку не включают; регистрация аккаунтов не запускается.
Код занятого ника неизвестен, автоматическая смена ника не включена.

Из корня репозитория:

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_character_creation_flow.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_game_login_probe.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_game_connection.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_selection_flow.py
```

Check `release-character-creation-flow` привязан к текущему SHA и зависимостям.
Предшествующие native доказательства ID / полей / handler остаются в
[producer](HEADLESS-CREATE-PRODUCER.md), [JSON keys](HEADLESS-CREATE-APPEARANCE-JSON-KEYS.md)
и [result handler](HEADLESS-CREATE-RESULT-HANDLER.md).
