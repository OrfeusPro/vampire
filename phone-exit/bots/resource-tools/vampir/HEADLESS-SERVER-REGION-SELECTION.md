# Выбор игрового сервера с учётом региона

20 октября 2026. Продолжение [отказа BlockedIp](HEADLESS-RESULT-ERROR-58.md).
Источник — код и данные установленного клиента, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Найденная ошибка выбора

Прежняя диагностическая политика выбирала наименьший корректный server ID
из всего ID 104. Свежая проверка теперь установила: server ID 101 находится
в группе региона **1 / KR**. Выход через JP сам по себе не менял выбранный
игровой регион. Теперь Login runner требует явный `--region` и ограничивает
выбор серверов этим регионом. Для JP был выбран server ID 251 / group ID 251.
Он снова вернул LoginResult 58; исправление выбора региона само по себе
не устранило отказ. [Реальная проверка](../../vampir-headless/LIVE-GAME-LOGIN.md).

## Числа и native gate

Конвертер 0x1457c7780 содержит initializer списка имён и значений:

| Имя | Значение |
| --- | --- |
| Common | 0 |
| KR | 1 |
| ASIA | 2 |
| TW | 3 |
| JP | 4 |

Исполнена native-ветвь инициализации до map builder 0x14450d970.
Настоящие инструкции задают пять чисел и адреса имён; FString constructor
и создание map захвачены ограниченными hooks. TLS guard / пролог и поиск
в готовой map не исполнялись. Значения не выводились из порядка CSV или ID.
Второй найденный ASIA-конвертер 0x1457e8ee0 имеет другую таблицу; его нельзя
смешивать с первой только по общему имени ASIA.

В ServerList_Update 0x145d4afe0 сервер соединяется с группой по server+0x08
и group+0x08. Найденный group value даёт регион по +0x20. Native-проверка:

- 0x145d4b56a вызывает настоящий singleton getter 0x145564550.
- 0x145d4b56f читает выбранный регион policy+0xa8.
- 0x145d4b575 сравнивает его с group+0x20.
- При совпадении переход на 0x145d4b585 разрешает lookup / копирование
  server record. При несовпадении и включённом region flag путь идёт на
  0x145d4b82d, минуя эту вставку. При выключенном flag регионы не фильтруются.

[replay-server-region-selection.py](replay-server-region-selection.py)
исполнил 32 сочетания: выбранный / фактический регион 1–4 и flag 0 / 1.
Getter и условные переходы настоящие; policy, group, stack flag — fixtures.
Group lookup и полный Update этим replay не исполнялись; их связь статически
проверена в Ghidra. Runtime использует **регион группы**, не произвольно
выбранный другой DWORD серверной записи.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/server-region-selection-replay.json`.
SHA256: `7d7d887569f237007659f146c356402a6278cb4708e5f948b2d9a33e09b95090`.

## Таблицы и SDK-настройки

Уже извлечённая таблица JoinedCountry / ServerRegionType / LocalServerRegion
содержит:

| JoinedCountry | ServerRegionType | LocalServerRegion | DefaultLanguage |
| --- | --- | --- | --- |
| KR | KR, ASIA, JP | KR | 7 |
| TW / HK / MO | TW, ASIA, JP | TW | 14 |
| JP | JP | пусто | 6 |

`ProjectRED-Windows-6196.csv` и `pakchunk1-Windows-1493.csv` совпали побайтно:
SHA256 `b96e6e3f2017f8e2b7cf00d7b87d17ade8bbb5bceb2c50269e282285c438e790`.
Первый источник: entry 6196, offset 148 232 192; второй — entry 1493,
offset 10 206 887. Полные extraction provenance-записи сохранены в отчёте.

Английская таблица регионов `ProjectRED-Windows-6105.csv`, SHA256
`af8a840ae62cd112c101bc29bad0435bb0fcde7944f87a5ecacefa7a39bb11c3`,
описывает KR как регион корейских пользователей, TW — Тайваня / HK / MO,
ASIA — общий для KR / TW / HK / MO, JP — общий также для JP.
Табличная политика не доказывает текущую серверную политику или доступ
конкретного IP. Автоматический выбор страны аккаунта по сети не добавлен.

GameSDK_Configure 0x14565a5d0 читает UseRegion из NetmarbleS и сохраняет
bool по config+0x228; ServerList_Update проверяет тот же offset через
getter 0x14563d960. UseNetmarbleJoinedCountry обрабатывается отдельно.
SDK response уже сохраняет gameRegion в module+0x68, но его дальнейший
потребитель ещё не связан с игровым Login. Ни страна выхода, ни страна
аккаунта, ни SDK gameRegion не объявлены взаимозаменяемыми.

## Runtime и проверка

`select_game_server_in_region` связывает record group ID с единственной
группой свежего ID 104 и проверяет raw_20. Неподходящий явный server ID,
отсутствующая / неоднозначная группа, неподдерживаемая ветвь ответа и
некорректный endpoint отклоняются. Без ID выбирается минимальный корректный
уникальный ID внутри заданного региона — локальная диагностическая политика.
Нет fallback в другой регион или трактовки availability / наличия персонажа.

`probe-selected-game-login.py` требует `--region KR|ASIA|TW|JP` до входа в SDK.
Старый Version-only probe сохранил прежний диагностический API; его selector
также получил необязательный region для использования Login runner.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-game-region-context-index.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-server-region-selection.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_server_region_target.py
```

Исследовательский index: `F:/PhoneExit Resources/Vampir/code-clues/game-region-context-index.json`.
SHA256: `b854e0eb442ccc5de0664ac9a96a55907ff343ae0ea10a940a7a1b0965c921cb`.
644 проверенных direct getter calls; два root не декодированы линейно.
Offset +0x100 кандидатов не означает идентичности объектов. Общие RIP / PE
helpers переиспользованы; не найденные ссылки не объявлены отсутствующими.

Ghidra 12.1.4: 359 функций / 168 предупреждений.
Экспорт: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-a0d5957ddf4a`.
Manifest SHA256: `cc58f70c82eb3ad4093677d7e6df94ef51bd1f05d4405ecbf19982f5285138af`.
functions.json SHA256: `d43c30ae2df8d9c635744a010871eb0a3dae5f447942dca68834dce3e8f98e25`.

Прошли 16 проверок: три region target, три Login runner, четыре Version
selector, три прежних endpoint и три Ghidra. Далее — полный SDK / country /
region context и причина оставшегося BlockedIp до успешного входа и персонажей.
