# Обработчик и отложенная копия обучения 1.13.16

26 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [чтения ID 9905](HEADLESS-TUTORIAL-UPDATE-11316.md).
Это offline native proof, без новых игровых входов и отправки команд.

## Связка регистрации

Повторно использованы сохранённые current registration fragments:
`code-clues/world-registrations-11316/3fb07bced4dde27d7cece52fc75af38c8c38a5390de03cea32524c8d8ba81b8c/manifest.json`.
Новая выгрузка огромного owner не выполнялась. Проверены точные текущие PE bytes:

| Связь | Адрес |
| --- | --- |
| Handler table LEA / store | `1467c0bea` / `1467c0bf1` |
| Packet allocation size 0x30 | `1467c0bf9` |
| CALL constructor ID 9905 `14584bda0` | `1467c0c0b` |
| R8 handler / RDX packet / RCX dispatcher | `1467c0c15` / `1467c0c18` / `1467c0c1b` |
| Registration CALL `1467cb6c0` | `1467c0c1e` |
| Handler table / slot +0x10 | `149dc5298` / `1467c9500` |

Handler `1467c9500` получает context через leaf `1464af340`, сохраняет пакет
из R8, затем передаёт его receiver `1464bf0b0` в RDX с R8D=0.
Getter — точные 8 байт `488b0581f01405c3`, чтение указателя по `14b5fe3c8`.
Это native global внутри клиента; отдельные headless owners не используют
общий глобальный объект и не читают память запущенной игры.

## Реальные границы функций

Collect отказал для getter без unwind: он проверяется как явный leaf, а не
выдаётся за unwind function. Следующий экспорт receiver остановился с
Decompiler block outside requested unwind ranges. Проверка инструкций показала
два E9 в самостоятельные roots `1464c38d0` и `1464c35d0`; они добавлены явно.
При таком запросе модель CALL_RETURN отделила хвостовые вызовы, экспорт прошёл.
Неудачные requests / logs сохранены; проверки границ не отключались.

Текущие экспорты под полным SHA:
`run-c3a2887c3d9b` — handler / receiver / обе ветви,
`run-529d4f47d8b6` — helper копирования `1464a78c0`.
Constructor повторно использован из `run-edd5235c81bf`.
Полные SHA и native leaf bytes закреплены в
`knowledge/native-contexts/tutorial-dispatch-11316.json`.

## Gate и очередь: 192 native-сценария

Receiver при R8B=0 получает объект через `14560adc0` и проверяет byte +0x30.
Значение `<6` направляет пакет в `1464c38d0`; иначе `1464c35d0` получает
context и packet+0x10. Ненулевой R8B обходит проверку состояния. Handler всегда
передаёт 0; это не флаг из тела `9905` и не новая команда API.

Отложенная ветвь получает ID через настоящий getter. Для `9905` native код
создаёт новый packet, вызывает его constructor и `1464a78c0`, затем добавляет
указатель в context+0x198. Count очереди находится по +0x1a0, capacity +0x1a4.
Копирование переносит metadata word +8 / byte +0xa, bool +0x18 и собственный
массив 0x18-байтных записей. Leaf `1456ea170` создаёт vptr элементов и переносит
raw08 / raw0c / raw10 / state без ссылки на исходный массив.

`replay-tutorial-dispatch-11316.py` исполняет целые handler / getter / receiver,
ветвь `9905` defer, constructor и оба copy helpers. Матрица содержит native
states 0 / 5 / 6 / 7, direct / handler вход, force 0 / 1, оба data flag,
count 0 / 1 / 8 / 64 и прежний queue count 0 / 1. 192 сценария прошли:
64 отложенных и 128 немедленных маршрутов. Предыдущая запись очереди сохранена,
аргументы немедленной передачи проверены, object / allocation guards сохранены.
Изменение исходных records и flag после defer не меняет queued copy.

State provider, успешная выдача памяти, fresh reserve и cleanup пустого прежнего
массива — fixtures. Очередь имеет подготовленную capacity, её рост не исполняется.
Немедленная цель application — fixture: проверяется передача аргументов,
а не выполнение server / local maps, bootstrap или запуск шага.
Другие ID в общей defer function, allocation failure и queue drain не покрыты.
Никакой native gate не приравнивается автоматически к headless ID 206.

Отчёт вне Git:
`code-clues/tutorial-dispatch-11316/2470ff7ad4becd85effd2bbfaaf040c7b69720ec94a863988fd50560408837c9/manifest.json`.

## Application: статический следующий участок

Целый текущий `1464c35d0` экспортирован и прочитан. По псевдокоду и инструкциям
он итерирует записи, использует первый uint32 в lookup `145c24be0`, вызывает
`14649fe90` для map context+0xa8 и проверяет существующую локальную запись
context+0x1c8. При локальном state 1 и серверном state 2 вызывает `1464c1b40`.
После обхода ненулевого count вызываются `1464c5210` и `1464ce8e0`.
Имена полей / таблиц и полные эффекты этих helpers ещё не перенесены на current SHA.

Следующая проверка — эти явные callees, fresh bootstrap / map application,
current queue consumer и связь готовности с lifecycle headless owner.
Пока runtime продолжает публиковать только last_received_message.
Старые ack / reset / произвольное движение не используются для обхода пробела.
