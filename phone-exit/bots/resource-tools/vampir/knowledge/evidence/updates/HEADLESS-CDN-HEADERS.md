# CDN: полный базовый GET header block

19 октября 2026. Продолжение [URI→request line](HEADLESS-CDN-URI.md).
Подтверждён полный блок заголовков для контекста по умолчанию, с пустыми
query/body/cookie/range и без дополнительных raw headers. Отправки в сеть нет.

## Источник и воспроизведение

Собранный Windows EXE, не исходный C++ проект:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Image base `0x140000000`; адреса VA. Реализация Android/iOS не проверена.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-cdn-headers.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_cdn_headers.py -v
```

Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-cdn-headers.json`, SHA256
`dda2fc591b6fc57441ec8fbde13699f2772507eb7ff80030370ad9ab2fb72bc6`.
Source/tool/prior-report SHA, 17 unwind roots / 48 fragments / 2888 инструкций,
11 native сценариев, format import и options leaf bytes, путь/SHA Windows CRT.
Capstone 5.0.6 / Unicorn 2.1.4; реальные аккаунты/процессы игры/сеть не использованы.

## Настоящая сборка

После native URI parser и prefix request-context constructor вызывается
header builder `0x1445e4b20`. Выполняются настоящие request-line, std::string
append/growth, Host builder и проверки условий остальных полей:

| Участок | VA |
|---|---|
| request line | 0x1445ec6f0 |
| Host + decimal port | 0x1445ec230 / 0x1445d8240 / 0x1445d49a0 |
| Content-Type | 0x1445ebbc0 |
| Content-Length | 0x1445eb970 |
| Cookie | 0x1445ebed0 |
| Range | 0x1445ec3d0 |
| std::string formatting | 0x1445da240 |

Allocator/free/memory/search/compare/security-cookie используют ограниченные shims.
Сами field builders/ветвление/конкатенация не подменяются. Форматирование
Referer/User-Agent проходит native formatting helper до импортированного
`__stdio_common_vsprintf` на `0x1445da2bf`. Для известных single-string formats
va_list pointers переводятся из synthetic memory в обычную память; вызывается
настоящая одноимённая функция записанного System32/ucrtbase.dll с options 2.
Не реализуется произвольная эмуляция variadic calls или пользовательских format strings.
Options getter `0x141435030` также исполняется, его bytes сохранены.

## Результат по умолчанию

Для искусственного URL `https://cdn.invalid/window/real/1_2_3/config.json`:

```http
GET /window/real/1_2_3/config.json HTTP/1.0
Host: cdn.invalid:443
User-Agent: Aqua/1.0

```

Каждая строка заканчивается CRLF; после User-Agent идёт ещё CRLF — блок
завершается `\r\n\r\n`. Host всегда включает десятичный port, в том числе
default 443 для HTTPS и 80 для HTTP. Исходный регистр host сохраняется; 00443
в URL становится 443 в Host. URI path/percent escapes сохраняются по предыдущему этапу.

В названном default GET нет Content-Length, Content-Type, Referer, Cookie,
Range и Connection. Это результат выполнения на пустых коллекциях/теле,
а не утверждение об отсутствии этих полей во всех запросах клиента.

Проверены 7 default cases: HTTPS/HTTP, явный port 8443, host case/double slash,
IPv4 literal/leading-zero port/percent escape и длинный путь. Loopback IP
используется только как строка; к нему никто не подключается.

Ещё 4 native override fixtures уточняют условия:

| Fixture | Наблюдение |
|---|---|
| context+0xa8=true | добавляется `Connection: Keep-Alive` |
| User-Agent empty | строка User-Agent отсутствует |
| User-Agent TestAgent/2.0 | значение заменяется буквально |
| Referer https://ref.invalid/ | Referer появляется перед User-Agent |

Назначение флага +0xa8 связано с полученным literal; реальная политика keep-alive
и поздние изменения этого флага ещё не исследованы. Overrides не выдаются за
фактическое состояние CDN-запроса после всех callbacks.

## Общий код

`vampir_core.cdn_request.encode_cdn_get_headers(url)` принимает ранее проверенный
URI subset и возвращает bytes default GET/1.0, Host с port и Aqua/1.0, включая
конечную пустую строку. Разрешён только этот профиль с пустым телом/query/cookie/
range и без дополнительных headers. POST, произвольные поля/override и transport
не реализуются. Локальный лимит блока 8192 байта, URI 4096 — не найденные лимиты игры.
Неподдерживаемые URI и CRLF injection отклоняются parser до сериализации.

CdnConfigRequestDraft.header_bytes выдаёт тот же блок для explicit HTTPS settings.
Сохраняются request_line/parsed URI и скрытие URL/host/path в repr. Наличие bytes
не означает отправку: DNS/TLS/socket/HTTP receive отсутствуют. Общий runtime
использует только stdlib, Windows CRT требуется исключительно analysis replay.

Семь default blocks совпали побайтно между native pipeline и общим encoder.
Интеграционный тест собирает settings→URL→draft.header_bytes и сравнивает с native
oracle. Другие тесты проверяют override observations, provenance, bounds и injection.

## Продолжение

Начальный этап: [граница и статус ответа](HEADLESS-CDN-RESPONSE-HEAD.md).
Далее проверить приём ответа: status/headers/body limits, Content-Length/chunked/
compression, JSON и callback order, а также TLS/redirect handling и request queue.
Фактические Game config values/late overrides ещё неизвестны. Сначала установить
подтверждённый endpoint; реальные CDN requests не выполнялись. network_ready=false.
