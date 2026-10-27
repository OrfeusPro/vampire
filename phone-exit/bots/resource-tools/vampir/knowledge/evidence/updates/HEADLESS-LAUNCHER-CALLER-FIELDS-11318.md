# Поля launcher caller 1.13.18 и переносимый план запроса

EXE SHA256 `d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Продолжение [JSON gates](HEADLESS-LAUNCHER-JSON-GATES-11318.md).
Целиком исполнены token 1444EECD0 (652 инструкции), sign-in 144503E10 (679),
BuildCode 1445323C0 (64) и одиннадцать инициализаторов по семь инструкций.
Bytes, полные unwind ranges, block/direct-flow coverage и conditional
fallthroughs проверены. Непросмотренные цели останавливают replay.

## Источники

| Экспорт | SHA256 | Содержимое |
| --- | --- | --- |
| run-5e88e50e265d | 8a81049376b63fbb7b476c3381aae08b0f9e325360c73ddf249f2108e3d799b4 | Оба caller |
| run-652644c53992 | fd7a0e84eb9246d0eaa4b57e864eb1e4c99d41609e705a3f4c1e1dd61a9f22ad | Восемь request key initializers |
| run-934cf393e845 | 66bf70420bebe7cf3530e7fee7cb01459629459bb78a0b309850954a696516d9 | BuildCode formatter |
| run-1a7e48a82067 | f63ec39e371d6757c1fa8889657fc53368f71723bcc46217823baac17fa38fe9 | Три инициализатора BuildCode |

Request keys связаны с literals/globals в
[предыдущей проверке](HEADLESS-LAUNCHER-REFERENCES-11318.md); здесь все восемь
инициализаторов выполнены снова. FString constructor и cleanup registration — fixtures.

## Что передают caller

Оба caller получают четыре строки через отдельные fixtures:

| Поле JSON | Цель вызова | Проверяемый аргумент |
| --- | --- | --- |
| nmDeviceKey | 1444ECB90 | Выходной FString |
| deviceKey | 1445293C0 | Settings receiver, выходной FString, R8B=1 |
| countryCode | 144528D00 | Тот же settings receiver, выходной FString |
| os | 1444ED250 | Выходной FString |

Значения из четырёх разных источников попадают в соответствующие key/value
пары начальной map. Проверяются сам диапазон четырёх пар, значения на границах
JSON wrappers/setters, результат перед serializer и перед transport.

Для token при ненулевом credential вызывается его virtual+8 GetObject.
В этот объект добавляются gameCode из settings data+38 и buildCode,
выбранный по byte data+48. Затем объект передаётся в поле `credential`.
При null credential поле отсутствует; четыре device fields сохраняются.

Для sign-in тело содержит только четыре device fields. Отдельная map получает
`launcherToken` из FString credential+58, включая пустое значение. Сам токен
не добавляется в тело. Оба caller запрашивают ключ `authUrl` и передают
suffix `launcher/token` либо `launcher/sign-in`. URL lookup/append — fixtures;
имя ключа и точный suffix/длина проверяются по фактическим аргументам.
Третий аргумент сериализатора равен 1, completion pointers — 1444DF0B0/1444DF1A0.
В каждом сценарии ровно один handoff в соответствующий transport wrapper.

Проверены восемь случаев: два разных synthetic профиля, token с credential
и без него, sign-in с пустым/непустым launcherToken. Второй профиль включает
кириллицу, кавычки и ASCII punctuation. Контейнеры fixtures сбрасываются между
случаями; это не проверка нескольких настоящих аккаунтов или параллельных сессий.

## BuildCode без подстановки formatter

| Значение | Инициализатор | UTF-16 literal | Global FString |
| --- | --- | --- | --- |
| A | 1411B3260 | 148A49F74 | 14B5648D8 |
| B | 1411B3290 | 1489F1014 | 14B5648E8 |
| C | 1411B32C0 | 1489FF7B8 | 14B5648F8 |

Инициализаторы и formatter исполняются native; constructor проверяет exact
literal и аргументы, предоставляя bounded буфер вместо реального allocation.
Все 256 byte inputs прошли: 1 → B, 2 → C, остальные → A. Такой же formatter
вызывается внутри token caller; settings bytes 1/2 дают вложенные B/C.

Copy thunk 1487F60D9 связан с PE import `VCRUNTIME140.dll!memcpy`: descriptor,
slot и имя проверены по source bytes. Копирование — bounded scratch fixture,
реальная CRT DLL не вызывается. Вызов allocation также заменён fixture.

## Сверка переносимого planner

Тест сравнивает текущие native captures с существующими
`plan_nid_launcher_token` и `plan_launcher_sign_in`. Для допустимого ASCII
профиля с явным NID credential33 либо непустым launcherToken совпали URL,
структура JSON, custom header и buildCode. Это две положительные сверки.

Шесть остальных случаев planner отклоняет: отсутствует нужный credential,
пустой token или присутствует Unicode-ввод. Это существующая более строгая
локальная политика; native handoff сам по себе не разрешает ослабить её.
Не сравниваются точные bytes настоящего engine writer или весь набор HTTP headers:
default headers отдельно проверены в [common transport](HEADLESS-LAUNCHER-COMMON-11318.md).

Tool `replay-launcher-caller-fields-11318.py`, тест
`test_vampir_launcher_caller_fields_11318.py`, check `launcher-caller-fields-11318`.
Артефакт: `code-clues/launcher-caller-fields-11318/8a9f946292585fe60d10ab35a0bb3e4dc80c137b10577e1c38bbdf6697560781/manifest.json`.

## Границы и продолжение

Identity acquisition, SDK/service/settings, credential GetObject, JSON/map
операции и writer, string allocation/append, capture allocation/cleanup и
transport — явные fixtures. Writer здесь Python json.dumps; значение credential
в одном профиле соответствует NID fixture, в другом является произвольным
synthetic объектом. Происхождение настоящих identity/token/credential не проверено.

Input callback пуст, owner weak reference и shared control blocks null.
Ошибки, active callbacks, конкурентный lifecycle и удаление последней ссылки
не выполнены. `native_execution=true`, `network_used=false`,
`profile_activation=false`, `compatibility=not_established`.
Runtime, профиль и онлайн-сессия не изменены; HTTP и квестовые команды не отправлялись.

Далее engine writers, response getters/dispatch и SDK context. Сверка planner
подтверждает эту часть подготовки запроса при явных входах, но не допуск нового
профиля, успешную авторизацию или серверное выполнение действия.
