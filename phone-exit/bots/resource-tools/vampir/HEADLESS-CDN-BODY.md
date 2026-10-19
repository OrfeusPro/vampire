# CDN: тело ответа и BOM, 19 октября 2026

После [ожидания тела по Content-Length](HEADLESS-CDN-RESPONSE-LENGTH.md)
исполнена функция получения тела `0x1445e6fc0` вместе с её строковыми helpers:
31 сценарий с искусственными байтами. Отдельно исполнены 9 сценариев проверки
статуса в начале CDN callback. Сети, процесса игры и файлов аккаунтов нет.

## Источник и воспроизведение

EXE: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это собранный код клиента, не исходный C++ проект.

Инструмент: [build-headless-cdn-body.py](build-headless-cdn-body.py).
Запуск: `python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-cdn-body.py`.
Используются закреплённые analysis Capstone 5.0.6/Unicorn 2.1.4.
Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/headless-cdn-body.json`.
SHA256: `6da611317d15d1db4a3246f36487c68750766df3dd1037c4b9872c0996db6c66`.
Записаны source/tool/prior report SHA, инструкции/offsets/bytes, body/header/
guard bytes, результаты, wide-constructor arguments и границы status slice.

## Подтверждённое поведение

`0x1445e6fc0` находит CRLFCRLF, получает количество доступных байт через
`0x1445e7440` и собирает строку. Полноту Content-Length сама функция не проверяет.
Без BOM копирует байты, включая NUL и некорректный UTF-8. При длине хотя бы 3
и префиксе EF BB BF удаляет ровно один UTF-8 BOM. Второй BOM сохраняется.
FF FE при длине только 2 остаётся сырыми байтами, FE FF не преобразуется.

При длине хотя бы 3 и FF FE native передаёт `body_bytes - 2` в wide constructor
`0x144416f20`, который считает **двухбайтовые units** и копирует вдвое больше
байт. Например, BOM + UTF-16LE `{}` имеет 4 байта после BOM, но запрашивает 8.
Это подтверждено аргументами и результатами исполнения. За концом тела в тесте
находятся явно выделенные guard bytes: NUL и затем нули либо Z, не память игры.
Замена guard меняет результат UTF-16LE; обычный UTF-8 результат не меняется.
Не утверждается, что живой клиент получает именно такой layout/guard.

`0x1445eb700` → `0x1445eb7f0` кодирует каждый uint16 unit отдельно в 1–3 байта.
Суррогатная пара для emoji даёт две трёхбайтовые последовательности, а не обычный
четырёхбайтовый UTF-8. Одиночные surrogate units тоже не отклоняются.
Строковые ctor/append/growth исполняются; memory/search/allocator/cookie helpers
имеют ограниченные shims. Здесь нет вызова gzip/decompression.

Prefix CDN callback `0x145642a30..0x145642a7b` пропускает в body branch статусы
200–299; остальные уходят в failure branch перед вызовом обработчика ошибки.
Проверены 0/199/200/204/206/299/300/404/uint32 max. Это только status gate,
не доказательство успешного принятия JSON/частичного ответа или всего callback.
Далее статически видны call `0x145642aad` → body helper и NUL scan
`0x145642ae0..0x145642ae7` перед UTF-8 conversion. Последняя часть не исполнялась.

## Общий декодер и явные отличия

[cdn_response.py](../../vampir-shared/vampir_core/cdn_response.py) предоставляет
`decode_cdn_body_text(body)` и `CdnLengthResponse.decode_text()`.
Поддержаны строгий UTF-8, удаление одного UTF-8 BOM и UTF-16LE с BOM.
Сохраняются whitespace и содержимое текста, без JSON parsing/config acceptance.
Лимит входа 2 МиБ; ошибки не включают содержимое ответа.

**Локальная политика**, не копия опасного поведения клиента: UTF-16LE читается
только в пределах body и проверяется строго, корректные surrogate pairs
объединяются, нечётные/незавершённые пары отклоняются. Один UTF-16LE BOM даёт
пустой текст. NUL отклоняется вместо неявного обрезания текста в callback.
UTF-16BE и автоматическое угадывание UTF-16 без BOM не поддержаны.
Native чтение guard и некорректные Unicode sequences не переносятся в runtime.

Семь тестов проверяют исходные bytes/SHA, 31 body replay и 9 status slices,
независимые результаты byte/unit преобразования, зависимость от guard, Unicode
ошибки, лимит и цепочку HTTP Content-Length → complete body → decoded text.
Общий код использует только stdlib; Android runtime ещё не проверен.

Далее: Content-Encoding/сжатие и fallback после неуспешного JSON, chunked/EOF,
полное принятие CDN config, реальные settings и TLS. `network_ready=false`.
