# CDN URI parser → GET request line

19 октября 2026. Продолжение [HTTP defaults](HEADLESS-CDN-HTTP.md).
Подтверждены выделение scheme/host/port/path и передача результата в native
request-line builder. Сеть, DNS, реальные config values и полный HTTP не проверены.

## Источник и воспроизведение

Собранный Windows EXE, не исходный C++ проект:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Image base `0x140000000`, все адреса VA. Android parity неизвестна.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-cdn-uri.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_cdn_uri.py -v
```

Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-cdn-uri.json`, SHA256
`a64ddfdb123c1be323d140f0ea67afb7aa465e14be85610424c5598f952b9f02`.
Source/tool/prior-report hashes, 10 unwind roots в 24 fragments, 2246 инструкций,
22 native сценария, provenance импорта atoi и фактического Windows CRT.
Используются закреплённые Capstone 5.0.6 / Unicorn 2.1.4.

## Что исполняется

URI constructor `0x1445e2d80` вызывает parser `0x1445e6460` на `0x1445e2dfd`.
Native parser получает std::string полного URL; сохранены helper constructor
`0x1421e1620`, std::string copy и используемые callsites.
Его выходной объект имеет:

| Поле | Offset |
|---|---|
| scheme std::string | +0x08 |
| host std::string | +0x28 |
| port uint16 | +0x48 |
| path std::string | +0x50 |

Тот же выходной объект передаётся настоящему request-line builder
`0x1445ec6f0`, с ранее проверенным request context по умолчанию GET/1.0.
Нет подстановки готовых полей URI или готовой строки GET между этими этапами.
Пустая query collection HTTP owner задаётся явно; query encoding не исполняется.
Allocator/free/CRT search/compare/copy/security-cookie — ограниченные shims.

Явный port преобразуется через `atoi`: импорт проверен на callsite
`0x1445e6b96`, DLL `api-ms-win-crt-convert-l1-1-0.dll`, функция atoi.
В replay этот вызов перенаправлен в настоящий Windows `System32/ucrtbase.dll`
с искусственной ASCII-строкой до 63 байт; путь/SHA256 DLL сохранены в отчёте.
Не эмулируется неизвестное поведение atoi на переполнении int32: таких входов
в наборе нет. Native запись результата в uint16 на `0x1445e6ba1` исполняется.
Это Windows analysis dependency, не зависимость переносимого runtime.

## Подтверждённое поведение

- `https://cdn.invalid/a` → scheme https, host cdn.invalid, port 443, path a.
- `http://cdn.invalid/a` → port 80; схема сохраняется, не приводится к регистру.
- Явный port 8443 сохраняется; 00443 преобразуется в 443.
- Отсутствующий путь или `/` → пустое path, строка запроса `GET / HTTP/1.0\r\n`.
- Удаляется ровно один slash: `//a` → path `/a`, GET target `//a`.
- Host spelling/percent escapes/dot segments не нормализуются: `CDN.INVALID`,
  `a%2Fb`, `a%20b`, `a/../b` сохраняются в найденных полях.

Пример полной offline цепочки:

```text
https://cdn.invalid/window/real/1_2_3/config.json
→ {https, cdn.invalid, 443, window/real/1_2_3/config.json}
→ GET /window/real/1_2_3/config.json HTTP/1.0\r\n
```

22 сценария включают короткие/длинные строки, явные порты, ASCII host case,
IPv4 literal и percent escapes. IPv4 127.0.0.1 используется только как строка
fixtures; никаких подключений к loopback или другому адресу здесь нет.

## Особенности native parser и локальные ограничения

Native разбор не является готовым валидатором адресов:

| Fixture | Наблюдение |
|---|---|
| HTTPS://cdn.invalid/a | scheme HTTPS, default port 0 |
| https://cdn.invalid:65536/a | результат atoi записан в uint16 → port 0 |
| https://cdn.invalid:abc/a | atoi → 0, port 0 |
| https://cdn.invalid:0/a | port 0 |
| https://cdn.invalid/a?x=1 | path содержит `a?x=1` |
| https://cdn.invalid/a#frag | path содержит `a#frag`, включая fragment |

Общий `vampir_core.cdn_uri.parse_cdn_uri_ascii` поддерживает только явно
ограниченный subset: lower-case http/https, host из ASCII alnum/dot/hyphen,
явный port 1..65535 из 1..5 десятичных цифр, строка до 4096 printable ASCII bytes
без пробелов. Userinfo, IPv6, backslash, query/fragment и non-ASCII отклоняются.
Это локальная политика, а не найденные лимиты или ограничения форматов игры.
Другие случаи native parser и прочие схемы не объявляются поддерживаемыми.

Frozen CdnUri сохраняет scheme/host/port/path без decode/IDNA/DNS. Host/path
скрыты из repr; request_target добавляет один ведущий slash. Это не проверка
DNS, доверенности узла или доступности сервиса.
Из 22 native fixtures 16 входят в этот subset и точно совпали с общим parser;
шесть отклонены локальной политикой. Подозрительное native поведение не копируется
в общий код как разрешённый URL для сети.

## Draft и продолжение

CdnConfigRequestDraft теперь валидирует URI при создании, хранит frozen uri
и даёт bytes property request_line. Это только первая строка с одним CRLF,
без headers, завершающей пустой строки и тела. Прямое создание draft также
отклоняет unsupported URI и non-HTTPS. URL/host/path не показываются в repr.
Проверка исходных bases и сохранения authority до/после сборки остаётся.

Следом full headers/body, дальнейшие overrides/request queue, TLS и приём
ответа: status/size/decode/JSON/callback order. Фактические Game config values
всё ещё неизвестны. Реального CDN request не было; network_ready=false.
