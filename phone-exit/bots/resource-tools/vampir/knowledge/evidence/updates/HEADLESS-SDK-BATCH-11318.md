# SDK/GMC2/NID 1.13.18: общий offline пакет

EXE SHA256 `d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c`.
Baseline SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Авторизации, HTTP-запросов, игровых команд и активации runtime не было.

## Сопоставление и экспорт

`align-sdk-batch-11318.py` использует фиксированные 34 roots. Поиск ограничен
±64 KiB вокруг каждого старого root; целые instruction/control shapes,
RIP/call references и локальные edges сверяются по двум полным SHA.
Одинаковые JSON wrappers определяются по native caller, одинаковые SDK
initializers — по точному global destination у потребителя и исходному literal.
Ни близость адреса, ни первая найденная строка не разрешают перенос.

Текущие ключевые функции:

| Роль | Адрес |
| --- | --- |
| Settings constructor, исполнен только prefix | `1444B3590` |
| GMC constructor | `1444C4510` |
| Game override | `145657D40` |
| GMC Start | `144508510` |
| GMC Refresh, URL slice | `1444FA480` |
| GMC HTTP headers slice | `1444FBEC0` |
| Platform getter | `144532710` |
| NID context, base-pair slice | `1450E3FB0` |
| NID OnDeepLink / OnResult | `1450F2FB0` / `1450F4170` |
| NID numeric / channel helpers | `1415E4460` / `144531C00` |

Девять готовых roots переиспользованы из прежних current exports. Новый
успешный пакет `run-9e79cd7f7832/details.json` содержит 26 roots: недостающие
25 и явный string-copy tail target. SHA256 экспорта:
`f36731187d67c70ad75494ff2b2b5535bd287de7d11f221bda0d55a8c8017856`.
Все 34 roots вместе покрывают шесть pinned exports в
`knowledge/native-contexts/sdk-batch-11318.json`.

Platform getter содержит код из 75 инструкций и таблицу из 15 RVA.
NID context — 972 инструкции и шесть RVA. Старый Ghidra export NID содержал
961 инструкцию: 11 native fallthrough instructions отсутствовали. Новый
alignment проверяет полный code prefix до последнего RET, затем отдельно
padding и таблицу; исторический пропуск не переносится. Все 21 table targets
сопоставлены с границами native instructions и прежними относительными целями.
Обычные roots проходят whole-unwind validation. Таблицы не выдаются за код.

`generate-sdk-replays-11318.py` записывает обычные Python-файлы для review,
новый source context и полный список SHA. Во время проверок нет динамического
AST adapter. Генератор переносит только явно сопоставленные адреса, читает
реальные bytes/leaf digests нового EXE, задаёт явный SHA общему harness,
переиспользует готовые shared exports. Неразрешённый адрес останавливает весь
набор до записи файлов. Поведение и fixtures прежних сценариев сохраняются.

## Общая модель tail calls

Первый пакет остановился на PC initializer: декомпилятор включил внешний
callee в unwind range. Добавление явного exit target позволило пройти дальше,
затем Start потребовал явного copy target. Все E9 tails фиксированного набора
проверены вместе; scope не расширялся обходом дерева callees.

Девять initializers переходят к `1487E976C`, Start — к `141441D60`.
Используется существующий `CALL_RETURN` analysis model. Native E9 не меняется.
У game override ещё есть E9 к setter `144552540` без собственной unwind записи.
Его точные bytes `890d9a5bc306c3` означают MOV global, ECX и RET.
Прежние bytes `890d9a3ec306c3` имеют ту же форму с переместившимся global.
Первоначальная ошибочная запись bytes была отклонена source guard до Ghidra;
после чтения обеих сборок исправлена. Неудачные попытки сохранены в библиотеке.

Collector разрешает этот leaf только для полного текущего SHA и точных семи
bytes. Python проверяет bounded instructions и конечный RET без внутреннего
branch/call, Java повторяет сверку bytes и допускает только MOV + RET в
ограниченном body. Leaf не становится экспортируемым unwind root. Только
реальный E9 выбранного caller получает модель; новые неуказанные callees
не исследуются. В EXE и runtime ничего не записывается.
15 тестов коллектора прошли, включая неверные bytes, branch, отсутствие RET
и превышение размера. Настоящий Ghidra collect подтвердил модель на SDK.

## Native replay и кандидат профиля

| Компонент | Native cases |
| --- | --- |
| Defaults / GMC constructor / SDK version | 9 |
| Game override / NMENV / SDK gates | 106 |
| PC initializer / platform getter | 12 |
| Constructor → Start до copy capture | 512 |
| URL builder | 27 |
| HTTP method / URL / headers capture | 73 |
| Geo bindings / native country update | 672 |
| NID base pairs до map construction | 32 |
| NID result с fixture primitives | 1100 |
| NID result с actual numeric/channel helpers | 1124 |
| Всего | 3667 |

У actual helpers дополнительно исполняются 112 numeric и 176 channel cases.
Это перекрывающиеся ограниченные сценарии, не 3955 настоящих авторизаций.
NID missing/empty/error inputs проверяются до adoption capture; отклонённые
варианты не передают credential fields дальше. CRT library, SHA и locale
закреплены. Реальные аккаунты, токены и device keys в fixtures не используются.

Общий `run-sdk-batch-11318.py` сначала проверяет исходный контекст и экспорты,
затем исполняет пакет один раз. Кэш зависит от текущего SHA, contexts, кода,
exports, portable helpers, Python, native distributions и CRT/locale.
Повреждённый report и изменившиеся inputs отклоняются. Assembly, geo и общий
check используют один report; отдельные потребители не повторяют native replay.

`build-sdk-profile-11318.py` повторно использует общий assembler, сверяющий
constructor → Start → URL → headers. Получен согласованный offline candidate:
SDK `5.2.11`, production zone 2, `https://apis.netmarble.com/gc2`,
group `netmarbles-v5`, market `nmp`, game `thered`, service `netmarbles`,
BuildCode 0 / строка A. Отсутствующее native значение не заменяется default.
У кандидата `runtime_enabled`, `network_ready`, `game_protocol_verified` false,
`supported_auth_flows` пуст. Рабочий `sdk-source-profile.py` не переключался.

Geo policy получила только новый проверенный SHA: clientIp и geoLocation,
отдельный isoCountry, сохранение прежней страны при A1/a1. Строгие локальные
IPv4/string/account/route/age guards сохранены; чужой account bundle отвергается.

## Проверки по версиям

Для SDK assembly прежний набор 1.13.16 остаётся историческим. Его сохранённый
profile report сейчас отклоняется с `Profile replay dependency changed:
native-request-harness-11316.py`; это не пройденная регрессия. Старый manifest
и SHA guard не подменялись. Новый набор 1.13.18 проверяется отдельно.

`research-workflow.py` поддерживает явные `source_variants` client check:
полный разрешённый SHA может выбрать test_pattern/dependencies/artifacts/
timeout. Variant не меняет ID, source scope, список SHA или offline review.
Выбранный вариант входит в definition/cache; неизвестный SHA остаётся
`requires_port`. Tooling variants запрещены. 17 workflow/variant тестов
и четыре tooling-scope теста прошли. Это инфраструктурное покрытие, а не
доказательство клиентской совместимости.

Штатный `prepare` подтвердил четыре passed checks: 13 client tests
(assembly 2, geo 5, общий пакет 6) и 17 tooling/variant tests, всего 30.
Две финальные группы адресов использовали те же check reports, без повторных
тестовых процессов. Дополнительные 15 collector и четыре tooling-scope tests
прошли отдельно; старый SDK assembly failure выше в этот результат не включён.

Подробные материалы в библиотеке ресурсов:

- alignment с полным code prefix:
  `knowledge/sdk-batch-alignment-11318/44ed8d215dcfe03c89f83d2da7e5340584569bc67fd304b800e5ec14a60f1771/manifest.json`;
- generated candidates / context:
  `knowledge/sdk-batch-generated-11318/1bbba6e42f4a1210eb7a0c0da2abcc7498fe6310fa13a29962d2a4c6aaa467cd/manifest.json`;
- единый подтверждённый native report:
  `knowledge/sdk-batch-verified-11318/11b23cfe291bbc33fc25a29d80e96204d8785a857206be5ad07dc28f308a8e01/manifest.json`;
- небольшой отключённый кандидат профиля:
  `sdk-source-profiles/4c4e14ff26d89804b7aa85798f3618703cbf5226e2ece80f7c99dcd5dda59de5/manifest.json`.

SDK assembly использует check report `d56b265863453555bdaa5e63e3c077102376c669068c395dd8dfb454fe5d2fb6`,
geo — `a7a9728659b0f835772529b838f9887b85fabdd84612edf3d2296d232a0a96bb`,
общий пакет — `e0c34566c90b8fc6bf0d5d920b4c20c855d0f8cb089e2639d66e01718abc2cb2`.
Каждый лежит в `knowledge/check-results/<SHA>/manifest.json`; полный SHA
файла равен имени каталога. Инфраструктурный report не используется как
доказательство native claim.

## Границы

Settings constructor исполняется только до прежней prefix boundary. URL,
headers, geo caller, NID base-pairs и OnResult используют объявленные slices;
остальные ветви подтверждены статически только в заявленных code/table links.
FString/allocator/storage/JSON/SDK/getters/backend/HTTP transport и adoption
setters остаются fixtures/captures. Actual CRT helpers не доказывают реальный
браузерный callback или сохранение credentials. NID query/extensions/browser,
полная инициализация, real startup settings и session не проверены этим пакетом.

Далее current launcher runtime profile/source guards и текущие CharacterList,
clock/game profile prerequisites, затем отдельная живая проверка. Исторический
успех входа и квестов 1.13.16 не объявляет готовой сессию 1.13.18.
