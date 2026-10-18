# CDN: граница и статус ответа, 19 октября 2026

После [сборки запроса](HEADLESS-CDN-HEADERS.md) проверены три функции клиента
на 52 искусственных ответах и обрезанных префиксах. Сетевых запросов нет.
Повторный аудит установки дал прежний [снимок обновления](CLIENT-RELEASE-AUDIT.md):
34 изменённых архива, один новый, EXE не изменился. Совместимость игровых данных
и сервера этим не подтверждается.

## Источник и воспроизведение

EXE: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это собранный код клиента, не исходный C++ проект.

Инструмент: [build-headless-cdn-response-head.py](build-headless-cdn-response-head.py).
Для исполнения нужны закреплённые Capstone 5.0.6 и Unicorn 2.1.4 из
игнорируемого analysis environment и Windows CRT. Путь/SHA DLL записан в отчёте.
Общее ядро от них не зависит.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/headless-cdn-response-head.json`.
SHA256: `19849b6a3b593fe8702c410fb54698c749686fc1b4db6473e3f1608623816e30`.
В нём source/tool/prior report SHA, инструкции с file offsets/bytes, короткие
getter anchors, импорт scanner, входные bytes и результаты каждого исполнения.

## Исполненные функции

| Адрес | Подтверждённое поведение |
|---|---|
| `0x1445e74f0` | Ищет CRLFCRLF и возвращает длину заголовка вместе с разделителем; без него 0 |
| `0x1445e75e0` | При длине заголовка больше 12 копирует первые 12 байт и сканирует статус через `%*s %d`; иначе 0 |
| `0x1445e7440` | Возвращает число уже имеющихся байт после разделителя; без него 0 |
| `0x1445da5d0` / `0x1445da610` | Получение указателя/размера буфера из response stream |
| `0x1418732e0` / `0x141872810` | Обёртка scanner и getter options; вызов импорта в `0x141873324` |

Поиск strstr заменён ограниченным shim только для CRLFCRLF. Каждый буфер явно
завершён NUL: организация накопления и завершающего байта в реальном receive loop
не доказана. Native поиск останавливается на NUL; это не двоичный поиск по длине.
Импорт `__stdio_common_vsscanf` подтверждён и вызван в настоящем Windows ucrtbase
с переводом одного int destination из synthetic va_list. Формат фиксирован,
вход ограничен 12 байтами. Другие CRT/memory helpers имеют ограниченные shims.

41 префикс ответа с Content-Length: 2 показывает переход incomplete → header
38 байт → наличие 0, 1 и 2 байт тела. Ещё 11 сценариев проверяют 404/301/500,
короткую status line, неверный протокол/статус, LF-only и NUL. Native scanner
принимает `anything 201`, `HTTP/2 200`, отрицательный статус (-1 как uint32
4294967295). Это наблюдения клиента, а не допустимые ответы общего ядра.
Байты тела после NUL учитываются в доступном размере, если разделитель перед NUL.

Receive `0x1445e95f0`, header parser `0x1445edb30` и CDN callback `0x145642a30`
сохранены только как статические корни продолжения. Полностью они не исполнены.
Семантика Content-Length/Content-Range и body decoding ещё не подтверждена.

## Общий ограниченный parser

[cdn_response.py](../../vampir-shared/vampir_core/cdn_response.py) предоставляет
`probe_cdn_response_head(accumulated_bytes)`: None до CRLFCRLF, затем immutable
version/status/header_bytes/headers. Дубликаты полей сохраняются в порядке
получения, get_all ищет имя без учёта ASCII-регистра. Тело не копируется и не
проверяется; его начало равно header_bytes. Содержимое полей скрыто в repr.

Строгие HTTP/1.0–1.1, статус 100–599, ASCII, token names, запрет folded fields/
control bytes, лимиты 16 КиБ и 64 поля — **локальная политика**. Native field
parser ещё не исполнен; эти правила не выдаются за его точную копию. Ошибки
вызывают ValueError без включения содержимого ответа. На вход подаются
накопленные bytes, а не независимые куски. Нет повторного сканирования тела.

Пять тестов проверяют source/CRT/инструкции, повтор всех 52 native сценариев,
независимые boundary/count assertions, переносимый subset, дубликаты,
неполное тело и ограничения. Наличие заголовка или status 200 не означает,
что получен полный ответ или пригодный JSON.

Далее: Content-Length/Range, тело/chunked/compression, JSON/callback acceptance,
реальные настройки CDN, TLS и очередь запросов. `network_ready=false`.
