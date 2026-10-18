# Vampir — самостоятельный сетевой бот

## Текущее состояние самостоятельного клиента, 18 октября

Выбранные send/receive пути, CRC/XOR/распаковка, queue ownership/partial send
проверены native replay; portable pump прошёл local IPv4 TCP.
[Transport и границы](../resource-tools/vampir/HEADLESS-SEND-DRAIN.md).
H04 начат: 24 SDK symbols/34 LEA/24 roots, 512 native escape calls, offline
code/refresh token request plans. [Авторизация](../resource-tools/vampir/HEADLESS-AUTH.md).
GMC2 config: 7 связанных функций и 256 native проверок выбора адреса.
Активный режим/параметры ещё не установлены.
[Источник и границы](../resource-tools/vampir/HEADLESS-SDK-CONFIG.md).
Параметры SDK и UTF-16 XOR конфигурации сохранены в общем ядре;
42 native проверки. [Доказательства](../resource-tools/vampir/HEADLESS-SDK-VALUES.md).
Полный вход по почте/паролю, SDK→game session, серверные endpoints и бой ещё
не реализованы. Все этапы/доказательства — в [TASKS](../vampir-headless/TASKS.md)
и [WORKLOG](../vampir-headless/WORKLOG.md); не повторять закрытые исследования.

Обновлено 18 октября 2026. **Сетевой клиент ещё не реализован.**
Главный общий вход проекта — [Vampir README](../vampir/README.md).
Найденные функции всех направлений — [общий FUNCTION-INDEX](../vampir/FUNCTION-INDEX.md).
Общий исполняемый код и данные — [vampir-shared](../vampir-shared/README.md).
Сетевой бот использует общий `vampir_core`, своей копии протокольного ядра нет.
Продолжение работ — [TASKS.md](TASKS.md), история — [WORKLOG.md](WORKLOG.md).

## Требования пользователя

- Работа на Windows без запущенной игры, включая вход по почте/паролю.
- 10–20 отдельных аккаунтов одновременно; у каждого свой персонаж/состояние.
- Сначала определить персонажа/место и фармить там; затем расширять сценарии.
- Лёгкая 2D-карта и онлайн-положение/цели/статусы; управление через карту.
  Нажатие точки не отправляет движение, пока координаты и команды не проверены.
- Небольшие размер сборки, память, CPU и трафик. Без рендера Unreal, кадров и OCR.
- Общее переносимое ядро для Windows и будущего Android. Предварительная основа:
  Python/asyncio, уже применяемый Chaquopy для Android. Окончательная пригодность
  зависимостей подтверждается ранним smoke-test на двух платформах.
- Учитывать примерно еженедельные обновления игры: извлечение данных,
  сравнение версий и проверка совместимости являются частью продукта.

## Границы и архитектура

Это отдельное направление, не изменение экранного `vampir/bot.py`.
Существующие исследования карты продолжаются независимо; подтверждённые
результаты используются через общий указатель. Полная карта не блокирует вход.

Ядро отделено от UI/ОС: протокол и сессии → актуальная модель мира → сценарии →
команды. Одна независимая async-сессия на аккаунт; отдельный процесс на аккаунт
не является требованием. Платформенные адаптеры: секреты (DPAPI/Keystore),
подтверждения входа, жизненный цикл/Android foreground notification/Stop.
Команды оболочки: connect/select_character/start_farm/stop_farm/disconnect;
будущее move_to включается только после отдельной проверки. Это план интерфейса,
не уже существующее API. После reconnect сначала получить authoritative state.

Визуализация: 2D-подложка/векторы выбранной области + живые слои персонажей,
целей и состояния. Использовать имеющиеся карты/преобразования только с их
подтверждёнными ограничениями. Сетевой обмен независим от частоты UI: выбранный
персонаж до 5 обновлений UI/с, общий список до 1/с, скрытая карта не перерисовывается.
Не загружать все миры/NPC/иконки сразу. Полная исследовательская библиотека,
EXE, PAK, Capstone/Unicorn и дампы не входят в runtime-сборку. Данные выдаются
компактными проверенными пакетами; debug packet capture выключен по умолчанию,
очереди/история/кеши ограничиваются. Секреты и содержимое авторизации не логировать.

Смерть, защитное сообщение, неизвестная версия/состояние и дополнительная
проверка входа приостанавливают действия соответствующего аккаунта. Фарм,
покупки и переходы не имитировать заглушками. Покупки/торговля/воскрешение/квесты
не входят в первый боевой цикл. Аккаунты не опрашивать до реализации протокола.

## Обновления игры

Не предполагать, что каждое обновление меняет протокол или только таблицы.
Хранить immutable снимки по build/SHA, version manifest и зависимости каждого
производного набора. Путь источника, версия (либо явно unknown), полные SHA256,
record/export/offset и версия инструмента обязательны. Перед переключением
проверять сериализацию, ID, вход, состояние и бой по реально затронутым связям.
Не смешивать карту и протокол разных неподтверждённых версий. Частичное извлечение
не заменяет последнюю проверенную сборку. Смена файлов — атомарная после проверок;
откат сохраняет старые данные, но не разрешает старый протокол на новом сервере.

Серверную совместимость нельзя вывести только из локального SHA. При unknown
response/version mismatch остановить команды и показать причину. Пока нет
доказанного межверсионного контракта, новая версия считается непроверенной.
Ручная команда проверки установленной игры — первый этап; расписание или
автоматическое скачивание/публикация пользователем пока не запрошены.

## Уже есть и где продолжать

Источники: `F:/PhoneExit Resources/Vampir`, установленный Windows EXE.
Полный baseline SHA и точные адреса — в общем FUNCTION-INDEX.
Есть каталог ресурсов, отдельные packet/handler/vtable связи, структуры статов,
подтверждённые ветви UI-входа; готового wire codec/login/бойца нет.

Первый инструмент нового направления:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-network-index.py
```

Выход: `F:/PhoneExit Resources/Vampir/code-clues/headless-network-index.json`.
Проверяет SHA EXE, точные строки и LEA на границах инструкций, хранит provenance.
Не запускает игру, не читает память процесса и не отправляет запросы.
Текущий результат: 27 symbols / 31 xrefs / 27 roots / 32 fragments / 1020 instructions,
missing=0, rejected=0, network_ready=false.

Проверка отчёта независимо от генератора:

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_index.py -v
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_native_entry.py -v
```

18 октября: 3 проверки отчёта и 7 проверок PE/unwind-инструментария прошли.
Проверки повторно декодируют xrefs из оригинальных байтов и сверяют SHA
фрагментов/строк. Отсутствие локальных данных означает skip, не подтверждение.

**H02 выполнен для 10 выбранных типов**: функции→vtable→constructor/ID и
reader/writer targets; пять result registrations. Полный отчёт и таблицы:
[HEADLESS-PACKET-BINDINGS.md](../resource-tools/vampir/HEADLESS-PACKET-BINDINGS.md).
ID Login/LobbyLogin совпадают, их схемы/регистрация различны; учитывать контекст.
Четыре независимых проверки, включая 10 native ID getter scenarios, прошли.
Wire encoding и сеть этим не проверены.

**H03a выполнен**: реальные native primitive/raw IO подтвердили Ping body16 байт
и Result 12 байт, 126 native scenarios/5 tests; codec в `vampir-shared/vampir_core/ping.py`, только
стандартная библиотека Python. [Доказательства и ограничения](../resource-tools/vampir/HEADLESS-PING-CODEC.md).
Это тела сообщений, не complete frames и не рабочее подключение.

Следующий конкретный шаг **H03b**: framing/send/receive/выбор dispatcher;
output roots144aa9da0/144aaccf0 и helpers1445f1230/144aa6ca0 ещё разобрать.
**H04**: SDK auth почта/пароль→сессия.

H03b.1: CRC32/XOR helpers подтверждены 252 native executions/5 tests;
общий `vampir-shared/vampir_core/frame_primitives.py`.
[Источники и ограничения](../resource-tools/vampir/HEADLESS-FRAME-PRIMITIVES.md).
Следом H03b.2: полный frame, receive validation, key/context/callbacks.

H03b.2a: native цельный send-A slice подтвердил 27 байтовый Ping frame и sequence
wrap (20 scenarios/5 tests). Общий `vampir_core/send_frame.py` умеет его собрать.
[HEADLESS-SEND-FRAME.md](../resource-tools/vampir/HEADLESS-SEND-FRAME.md).
Продолжение — receive validation/context/key H03b.2b; сетевого подключения нет.

H03b.2b partial: length probe 156 native cases и wrapper 13 cases; статически связаны
game peer callback и Dispatch. Общий receive_frame.py проверяет полноту/лимиты,
не CRC/packet fields. [Доказательства](../resource-tools/vampir/HEADLESS-RECEIVE-ENVELOPE.md).
Следом transport caller, integrity/keyflow и полный входной layout.

Смена peer key теперь связана с PktKeyChangeNotify(ID11): ackPktKeyChanged(ID12)
передаётся в send до setter, оба payload8 байт. 20 native flow cases/5 tests;
общий key_change.py. [Доказательства](../resource-tools/vampir/HEADLESS-KEY-CHANGE.md).
Первичная авторизация, полный receive layout и send queue остаются unknown.

Первый raw receive stage подтверждён 62 native сценариями / 5 тестами:
size 23/compressed flag, копирование/распаковка и compaction. Общий transport_header.py
распознаёт признак сжатия, извлекает несжатые кадры; общий decompressor ещё не готов.
[Доказательства](../resource-tools/vampir/HEADLESS-TRANSPORT-STAGE.md).
Далее listener loop/второй framing и send queue; сетевого подключения нет.
Действующие данные не перезаписывать
прогонами новых гипотез; новый результат ссылать в общем индексе и журнале.
