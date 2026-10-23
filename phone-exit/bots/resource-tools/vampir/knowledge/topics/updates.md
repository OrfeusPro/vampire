# Версии, snapshots и обновления данных

## Установлено

Есть аудит установленного клиента, release / patch snapshots, индексы
извлечений и источников, проверка SHA и повторное извлечение изменившихся данных.
Полный SHA и выборочный отпечаток в доказательствах различаются.
[Аудит](../evidence/updates/CLIENT-RELEASE-AUDIT.md),
[индекс релиза](../evidence/updates/CLIENT-RELEASE-INDEX.md).

ClientVersion из windows.manifestlist связан с числом Login; для теста
использована ревизия 258392. Отдельные pakchunk revisions не равны автоматически
общей ревизии клиента. [Связь](../evidence/updates/HEADLESS-PATCH-CLIENT-VERSION.md).
CDN / GMC2 probes сохраняют свежие публичные snapshots; это не доказательство
полной совместимости всех ресурсов и протокола новой версии.

## Открыто

Единый продуктовый процесс: версия / SHA → diff источников → переизвлечение →
проверка затронутых таблиц, адресов, UI и геометрии → runtime-регрессии.
Проверка только заголовка архива или части файлов не закрывает весь pipeline.
Windows / Android parity и перенос старых mappings требуют отдельной проверки.

<!-- evidence-inventory -->
## Подробные разборы

Это источники и история проверок; наличие документа не означает завершённую live-функцию.

- [Проверка обновления клиента, 19 октября 2026](../evidence/updates/CLIENT-RELEASE-AUDIT.md)
- [Новые индексы и CSV после обновления, 19 октября 2026](../evidence/updates/CLIENT-RELEASE-INDEX.md)
- [SDK / NID после обновления EXE, 21 октября 2026](../evidence/updates/CLIENT-SDK-PROFILE-UPDATE.md)
- [Archive и полные тела Version / Login в 1.13.16](../evidence/updates/HEADLESS-ARCHIVE-WIRE-11316.md)
- [CDN: тело ответа и BOM, 19 октября 2026](../evidence/updates/HEADLESS-CDN-BODY.md)
- [Источник окружения SDK: CDN config](../evidence/updates/HEADLESS-CDN-CONFIG.md)
- [CDN: запасная расшифровка тела, 19 октября 2026](../evidence/updates/HEADLESS-CDN-FALLBACK.md)
- [CDN: полный базовый GET header block](../evidence/updates/HEADLESS-CDN-HEADERS.md)
- [CDN HTTP: default GET/1.0 и offline draft](../evidence/updates/HEADLESS-CDN-HTTP.md)
- [CDN: JSON, fallback и окружение SDK, 19 октября 2026](../evidence/updates/HEADLESS-CDN-JSON-FLOW.md)
- [CDN: AppVersion, Windows platform и общий offline URL](../evidence/updates/HEADLESS-CDN-PREPARATION.md)
- [CDN: граница и статус ответа, 19 октября 2026](../evidence/updates/HEADLESS-CDN-RESPONSE-HEAD.md)
- [CDN: Content-Length и ожидание тела, 19 октября 2026](../evidence/updates/HEADLESS-CDN-RESPONSE-LENGTH.md)
- [Выбор базы CDN и конфигурация Game](../evidence/updates/HEADLESS-CDN-SELECTION.md)
- [CDN: выбор сервера и данные лобби, 19 октября 2026](../evidence/updates/HEADLESS-CDN-SERVER-LIST.md)
- [Актуальный источник CDN: ограниченные проверки, 19 октября 2026](../evidence/updates/HEADLESS-CDN-SOURCE-PROBE.md)
- [CDN URI parser → GET request line](../evidence/updates/HEADLESS-CDN-URI.md)
- [CDN URL: завершающая сборка строки](../evidence/updates/HEADLESS-CDN-URL.md)
- [Строка версии пакетов 1.13.16](../evidence/updates/HEADLESS-COMPILED-TAG-11316.md)
- [NetworkSetting: callback вызывается при регистрации](../evidence/updates/HEADLESS-CONFIG-STARTUP.md)
- [RequestGMC2: аргументы GET и условия заголовков](../evidence/updates/HEADLESS-GMC2-HEADERS.md)
- [GMC2: native сборка URL из явных значений](../evidence/updates/HEADLESS-GMC2-URL.md)
- [GMC2 DecryptXOR: 16-битные единицы и пропуск нуля](../evidence/updates/HEADLESS-GMC2-XOR.md)
- [Описания модулей base и patch](../evidence/updates/HEADLESS-MODULE-DESCRIPTORS.md)
- [Version / Login 1.13.16: порядок полей и отказы writers](../evidence/updates/HEADLESS-PACKET-WRITERS-11316.md)
- [PAK: ключ callback, каталог и упакованный Game config](../evidence/updates/HEADLESS-PAK-CONFIG-RECOVERY.md)
- [ClientVersion из manifestlist до числа игрового Login](../evidence/updates/HEADLESS-PATCH-CLIENT-VERSION.md)
- [Публичная CDN-конфигурация получена и разобрана](../evidence/updates/HEADLESS-PUBLIC-CDN.md)
- [Реальный публичный GMC2 response и SDK constants](../evidence/updates/HEADLESS-PUBLIC-GMC2.md)
- [Ранний обмен новой версии: проверка источника предварительного кадра](../evidence/updates/HEADLESS-RELEASE-BOOTSTRAP.md)
- [Источник часов Ping: UTC, Unix epoch и поправка в минутах](../evidence/updates/HEADLESS-RELEASE-CLOCK.md)
- [Новый compiled tag Version / Login и код 1](../evidence/updates/HEADLESS-RELEASE-WIRE-TAG.md)
- [Возобновляемая сверка 1.13.14 → 1.13.16](../evidence/updates/HEADLESS-RESUMABLE-UPDATE-11316.md)
- [Полный string writer 1.13.16 с native UTF-8](../evidence/updates/HEADLESS-STRING-WRITER-11316.md)
- [Связанные проверки в команде обновления](../evidence/updates/HEADLESS-UPDATE-CHECK-DISPATCH.md)
- [UTF-8 helpers 1.13.16: нативное преобразование и границы буфера](../evidence/updates/HEADLESS-UTF8-11316.md)
- [Version 1.13.16: настоящий NM provider и getter](../evidence/updates/HEADLESS-VERSION-NM-11316.md)
- [Version: платформа и контекст 1.13.16](../evidence/updates/HEADLESS-VERSION-PLATFORM-11316.md)
- [Version prepare 1.13.16: целая функция с явными входами](../evidence/updates/HEADLESS-VERSION-PREPARE-11316.md)
