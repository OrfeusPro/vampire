# Передача аргументов launcher transport 1.13.18

EXE SHA256 `d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Продолжение [request references](HEADLESS-LAUNCHER-REFERENCES-11318.md).
Явные корни: token wrapper `0x144522f90`, sign-in wrapper `0x144523110`.
Полный экспорт `run-236277aa9d0b`, SHA256
`83c2cc9ec957ea9ca3d1dfefbc73b09e2252417aeb73d45199381789c640ce53`.
Проверены source bytes, декодирование инструкций и complete block/direct-flow
coverage, включая conditional fallthroughs. Непросмотренная цель останавливает replay.

## Что выполнено

Обе полные функции исполнены в Unicorn до явно подставленного общего обработчика
`0x1445231a0`. Для каждой проверены пустой callback, встроенный capture и capture
в отдельном объекте: всего шесть случаев. Fixtures не выполняют сетевые операции.

Обе функции разыменовывают wrapper контекста и передают исходные указатели
output, route и body общему обработчику. Callback перемещается: исходные поля
function и heap storage обнуляются до передачи. Sign-in сохраняет переданный
контейнер headers, переносит capture без копирования и возвращает output pointer.
Token создаёт пустой локальный контейнер, копирует активный capture через его
virtual method и после передачи очищает локальный контейнер, затем уничтожает
перемещённый исходный capture. Проверяются receiver copy/destruction и порядок
вызовов. Borrowed manager/route/body/headers/heap object не изменяются.

Это проверка calling convention и владения на данной границе. Названия headers,
body и callback здесь обозначают роли указателей в цепочке; фактические JSON,
HTTP headers и формат запроса общий обработчик ещё не подтвердил.

## Воспроизведение

Tool `replay-launcher-transport-11318.py`, тест
`test_vampir_launcher_transport_11318.py`, check `launcher-transport-11318`.
Артефакт: `code-clues/launcher-transport-11318/6aec8070b58308a465d1e96f23287d302802dd6ec672b73d5df808b3331b3eb7/manifest.json`.

Общий harness теперь принимает отдельный полный source SHA и явную настройку
memcpy thunk. Прежние значения 1.13.16 сохранены по умолчанию; здесь неиспользуемая
memcpy fixture отключена, старый адрес не переносится в новую сборку.
Регрессия `test_vampir_quest_environment_update_11316.py` прошла.

## Границы и продолжение

Common transport, virtual copy/destruction, empty-map cleanup и stack cookie —
fixtures. Capture и контейнеры synthetic; sink потребляет callback, но не вызывает
его. Ошибки выделения, непустые контейнеры и асинхронный lifecycle не проверены.
`native_execution=true`, `network_used=false`, `profile_activation=false`,
`compatibility=not_established`. Текущая игровая сессия не перезапускалась.

Следом — общий transport `0x1445231a0`, реальные сериализация/headers, затем
response getters/dispatch и SDK/GMC2 context. Этот результат не допускает
новую авторизацию и не подтверждает выполнение квестового действия.
