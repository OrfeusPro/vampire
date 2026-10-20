# CDN HTTP: default GET/1.0 и offline draft

19 октября 2026. Продолжение [подготовки CDN URL](HEADLESS-CDN-PREPARATION.md).
Подтверждены значения контекста запроса и построение первой строки HTTP.
Полные headers, тело, TLS, очередь/сеть и приём ответа ещё не проверены.

## Источник и воспроизведение

Собранный Windows EXE, не исходный C++ проект:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Image base `0x140000000`; все адреса VA. Android parity неизвестна.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-cdn-http.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_cdn_http.py -v
```

Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-cdn-http.json`, SHA256
`e75b2e0bfdf86300f4d851a33dfa388e556c966f020e0aa2b868e2f1c3dd417c`.
Он сохраняет source/tool/prior-report SHA, 12 unwind roots в 33 fragments / 3131 инструкция,
literal references и 16 native сценариев. Capstone 5.0.6 / Unicorn 2.1.4.
Игра, аккаунты, сеть и память процессов не использовались.

## Связь CDN с HTTP объектом

В Initialize CDN после сборки URL выполняются:

| Callsite | Target | Уровень подтверждения |
|---|---|---|
| 0x14563fcda | 0x1445e7be0 | Фабрика выделяет объект и вызывает ctor 0x1445e21f0 |
| 0x1445e234b | 0x1445e25d0 | Ctor создаёт request context по owner+0x320 |
| 0x14563fcea | 0x145636d00 | Привязка observer/context; весь callback lifecycle не исполнен |
| 0x14563fd0d | 0x1445ea140 | Передаётся разобранный URL, R8/R9=0 |
| 0x1445ea1a8 | 0x1445e4870 | При R8=0 — AddPendingRequest; очередь статически прослежена |
| 0x1445e4b67 | 0x1445ec6f0 | Построитель headers вызывает построение request line |

Root AddPendingRequest содержит одноимённую диагностику. Его drain/socket/таймеры
не исполнялись. Также сохранены roots `_SendRequest` и HTTP callback CDN;
имя diagnostic само по себе не означает проверки всего поведения функции.
Промежуточные URI constructor/parser/copy здесь только статическая связь.

## Реальное исполнение контекста и строки

Prefix ctor `0x1445e25d0..0x1445e26ac` устанавливает:

- method code по context+8 = 1;
- HTTP version std::string по +0x10 = `1.0`;
- поле User-Agent по +0x58 = `Aqua/1.0`.

Участок заканчивается перед генерацией случайного значения в остальной части
конструктора. Назначение этого дальнейшего значения пока не заявляется.
HTTP owner ctor затем устанавливает context.owner; в replay это явный fixture.

Настоящий request-line builder `0x1445ec6f0` сопоставляет method code 1 с
literal `GET /` на `0x1445ec8ad`, добавляет path, ` HTTP/`, version и CRLF.
Исполняются native std::string append `0x1445ddc80` и growth `0x1445d8310`.
Allocator/free/memcpy/memmove/cookie check — ограниченные shims. Сама сборка
строки и выбор метода не подменяются. Выполнение не вызывает socket/TLS/HTTP API.

16 сценариев: 8 путей × заполнение контекста 00/A5. Проверены пустой путь,
длинные строки, SSO boundary, исходный leading slash и double slash.
Для `window/real/1_2_3/config.json` получается:

```http
GET /window/real/1_2_3/config.json HTTP/1.0
```

Настоящая строка заканчивается `\r\n`. Parsed-path fixture передаётся без URI
parser; `'/a'` даёт `'GET //a HTTP/1.0\r\n'`. Нельзя по этому тесту утверждать,
что реальный parser сохраняет либо удаляет начальный slash. Query collection
владеющего объекта пуста; query encoder и тело запроса не исполнялись.
Поле User-Agent подтверждено, но включение его в полный wire header ещё не проверено.

## Общий offline draft

`vampir_core.cdn_request.draft_cdn_config_request` принимает обязательные
normal/qa/prefix/app_version/platform_code, собирает URL ранее проверенным кодом
и возвращает frozen CdnConfigRequestDraft с URL и defaults GET/1.0. URL скрыт
из repr; сетевых операций, DNS, headers/body serializer или автоматического
запуска нет. Это кандидат запроса, не законченная wire-реализация.

Локальная политика строже native concat: обе базы проверяются до сборки,
затем проверяется результат. Требуется HTTPS/непустой host/корректный port,
запрещены userinfo, query/fragment включая пустые `?/#`, backslash, whitespace
и non-ASCII. Это не подтверждение доверенного сервера или его доступности.
Валидация базы до concat важна: hostless `https://` иначе может стать
`https://window/...` после присоединения platform. Тест воспроизвёл этот случай,
исправление проверяет исходную базу независимо от результата. Дополнительно
сборка не может менять authority выбранной базы: https://host без trailing path
иначе превращает имя host в hostwindow. Нормативная строковая concat остаётся
в отдельном helper; draft отклоняет такой адрес до сетевого использования.

Продолжение: [native URI parser и GET-line pipeline](HEADLESS-CDN-URI.md).
URI strict subset проверен, полный HTTP и actual config ещё открыты.

## Продолжение

Нужно проверить URI parsing, полные headers/body и поздние изменения defaults,
очередь/callbacks, статусы/limits/decode ответов и TLS/redirect policy. Отдельно
найти фактические Game config bases/prefix/version; пока их нет, реальный CDN
request не отправляется. Затем CDN JSON/Zone → GMC2/DECKEY/constants → вход.
network_ready=false, полный вход и игровой бот ещё не готовы.
