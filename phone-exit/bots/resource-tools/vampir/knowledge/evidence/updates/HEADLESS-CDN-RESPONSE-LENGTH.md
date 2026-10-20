# CDN: Content-Length и ожидание тела, 19 октября 2026

После [границы и статуса](HEADLESS-CDN-RESPONSE-HEAD.md) проверены header lookup,
преобразование Content-Length и ветвление receive по размеру. Это 30 завершённых
native сценариев и один сценарий, остановленный по лимиту инструкций.
Полный HTTP receive loop и полный header parser не заявляются исполненными.

## Источник и воспроизведение

Код клиента: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это EXE, не исходный C++ проект. Файлы аккаунтов и процесс игры не используются.

Инструмент: [build-headless-cdn-response-length.py](../../../build-headless-cdn-response-length.py).
Запуск: `python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-cdn-response-length.py`.
Он использует закреплённые analysis Capstone 5.0.6/Unicorn 2.1.4 и Windows CRT.
Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/headless-cdn-response-length.json`.
SHA256: `3f8196e1da4475986b401a6ef246c8a0eec13498266e961605e2cf0236e563de`.
В отчёте source/tool/prior SHA, CRT path/SHA, инструкции/offsets/bytes,
импорты, литералы и входы/результаты. Общему runtime Windows CRT не нужен.

## Исполненная цепочка и ограничения

1. Prefix `0x1445edb30..0x1445edc9b` исполняет обе настоящие lookup:
   Content-Length и Content-Range, с литералами из EXE, а не подменёнными ключами.
2. Helper `0x1445ea4a0` ищет CRLF-строки, сравнивает имя без учёта регистра,
   принимает `:` и `=` сразу после имени. Для occurrence 0 выбирает первое
   совпадение. `0x1445dbe60` → `0x1445dc0f0` / `0x1445dbef0` обрезают whitespace.
   Все эти функции и строковые copy/growth исполняются native.
3. Средняя часть parser с проверкой Content-Range, formatter и диагностикой
   **пропущена**. Наличие захваченного range не доказывает его обработку.
4. Slice `0x1445edf20..0x1445edf46` конвертирует непустую length через actual
   Windows `atoi`, расширяет signed int и пишет owner+0x4d0. Пустая строка
   оставляет прежнее значение. Начальное значение — явный fixture 0 или 7;
   constructor/reset lifecycle этого поля ещё не доказан.
5. Receive slice `0x1445e968c..0x1445e96dd` читает младшие 32 бита length,
   вычисляет total received minus header size и выполняет unsigned compare.
   Заявлено больше, чем получено → ветка `0x1445e9cb5`; иначе `0x1445e96dd`.
   Log/progress calls имеют capture shims. Последующая обработка не исполнена.

Буферы искусственные, contiguous и явно NUL-terminated. strstr/strncpy/memory/
allocator имеют ограниченные shims. Импорты `_strnicmp` и `atoi` подтверждены
и выполняются в настоящем CRT из указанного DLL. Это не сетевой тест.

Подтверждённые особенности: `+2` и `2junk` дают 2, `nope` даёт 0, `-1` даёт
signed -1, который сравнивается как uint32 4294967295. Проверенные положительные
overflow строки дают 2147483647 в этом Windows CRT. Первое из двух разных
Content-Length определяет размер. `Content-Length :` и `X-Content-Length`
не совпадают. Пустое/отсутствующее значение сохраняет fixture, включая 7.
Нельзя использовать это как доказательство поддержки EOF или chunked.

Один folded-field fixture (`Content-Length: 2` и следующая строка ` 3`)
достиг лимита 32768 инструкций в lookup. В отчёте записаны остановка/последние
calls. Это bounded abort в эмуляции, не утверждение о зависании живой игры.
Общий head parser уже отклоняет folded fields.

## Общий код и проверка

[cdn_response.py](../../../../../vampir-shared/vampir_core/cdn_response.py) добавляет
`take_cdn_length_response(accumulated_bytes)` и immutable CdnLengthResponse.
None означает неполные header/body, результат содержит head, raw body и consumed.
Тело извлекается строго по length; последующие bytes остаются вызывающему коду.
Заголовок сканируется в прежнем лимите, тело копируется только после полноты.

**Локальная политика**, более строгая, чем обнаруженные особенности клиента:
status 200, один десятичный Content-Length (1–10 цифр), максимум 2 МиБ тела,
без Transfer-Encoding/Content-Range и с отсутствующим либо единственным
Content-Encoding: identity. Идентичные дубликаты length тоже отклоняются.
Недопустимое и неподдерживаемое вызывает ValueError без содержимого ответа.
Это промежуточный профиль: chunked, EOF framing, redirects, compressed/ranged
responses ещё требуют реализации, а не считаются необязательными для продукта.

Шесть новых тестов проверяют source/import/CRT/инструкции, 30 native replays,
bounded abort, независимый unsigned compare, каждую точку обрезания ответа,
бинарное тело/NUL, trailing bytes, bounds, дубликаты и unsupported framing.
Body bytes ещё не означают пригодный JSON или применённый config.

Следующий результат: [body/BOM decoder и отличия](HEADLESS-CDN-BODY.md).
Продолжение: native body decoding/BOM, Content-Encoding и chunked/EOF paths,
JSON/callback acceptance, фактические CDN settings и TLS. `network_ready=false`.
