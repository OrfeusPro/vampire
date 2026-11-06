# Текущий producer Create и числовая внешность

EXE SHA256 `03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
База переноса `98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Пакет `create-producer-current-v1` проверяет целые тела и локальные переходы
15 функций. Карта 82 адресов согласована между всеми callsites и RIP references.
Дополнительно проверены четыре метода числовой таблицы, четыре коротких leaf,
потребляемые vtable slots, строка `VoiceType`, sentinel и dispatch argument.

| Роль | Текущий адрес |
| --- | --- |
| Owner constructor | `0x146444530` |
| Raw class getter | `0x14644bf30` |
| Create producer | `0x14644bc30` |
| JSON outer | `0x146449d10` |
| JSON entry / key | `0x145673460` |

Owner vtable `0x149ca7f30` связывает producer в slot `+0x48` и getter
в slot `+0x90`. Constructor связывает ту же таблицу. Он сохраняет прежний
контракт копирования пола UI `+0x364` в owner `+0x30` только при подходящем
источнике. Getter читает class ID из UI `+0x360`. Отсутствующий UI не задаёт
пол автоматически. Границы provider fixtures сохранены.

Producer копирует ник из PlayerState `+0x368/+0x370`, класс из virtual getter,
пол из owner `+0x30`, девять scalar bytes из owner `+0x9..+0x11` в прежнем
порядке. JSON helper получает `owner+8`. Его результат помещается в packet,
затем вызывается текущий send wrapper. Пустой ник сам producer не запрещает;
runtime обязан подготовить непустое имя и одну попытку после свежего пустого списка.

Переиспользованы 37 [producer-сценариев](HEADLESS-CREATE-PRODUCER.md),
36 [JSON-сценариев](HEADLESS-CREATE-APPEARANCE-JSON-KEYS.md) и
144 [constructor/getter сценария](HEADLESS-CREATE-CLASS-SOURCE.md).
Текущий пакет writer/result закреплён отдельным parent proof.
Новые native матрицы не запускались. Один отсутствовавший JSON outer экспорт
получен ограниченным collect; producer использован из готового экспорта.

Native JSON setters подтверждают числовое содержание. Имена групп и ID 1–7
сохранены в прежних BoneGroup данных; полный SHA установленного pakchunk100
совпадает с исходным архивом. Latin numeric rules остаются явной политикой
бота. Порядок ключей, пробелы и native запись чисел этим не доказываются.

Engine/UI/culture/rules, initialized text history, storage/free, setters,
JSON writer и dispatch сохраняют границы прежних fixtures. Холодная
инициализация форматтера и destructor ветви с низкими refcount не исполнены.
Loaded asset, полный движок и онлайн-создание не заявляются подтверждёнными.
Два явных кандидата внешности и текущая Class CSV подготовлены
[отдельным пакетом](HEADLESS-VIPER-APPEARANCE-CURRENT.md).

Проверка `create-producer-current` включена в `on_update`, частичный контракт
`character-create`, общий tooling и кэш. Изменение source, таблицы, зависимости,
правила или parent proof меняет ключ либо даёт конкретный отказ.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-create-producer-current.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_create_producer_current.py
```

Следующий пакет — текущая Viper factory и отдельный допуск runtime создания
с постоянным журналом неопределённого исхода. Коды занятого ника не установлены.
Неизвестный результат не разрешает повторную отправку Create.
