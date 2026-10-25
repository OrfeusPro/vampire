# Потребители сохранённых привязок: чтение и запись строки

25 октября 2026. Продолжение [native hash / общего reader](UI-CONFIG-HASH-11316.md).
Источник EXE SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Offline replay, synthetic память; игра и реальные профили / конфигурации не меняются.

## Поиск и источники

Задание `d82b0b15f6fb17c0cf0435319d4a64865cdb6f5ec1503cdd5695de6dc37fb7ab`
зафиксировало известный reader как source/context для узкого поиска RIP LEA
по 14b186130. Найдено 15 byte-pattern candidates, их владельцы определены
по unwind. Это не полный список всех обращений к глобальному объекту.

Выбраны три коротких roots в задании
`399dd86f96fce3f28425fa41dbb26671d1c0097eef593cb8a7b18617bcc37e30`:
1445cb6c0 / 1445cbd00 / 1445d6ec0. Collector завершился с collected / пустой
очередью. Ghidra материал:
`ghidra/request-exports/<полный SHA EXE>/run-dae2243fbae2/details.json`, SHA256
`cba3a568ef1da9ab84757b2c81c319df60abde13f88eb386b4a1cd89471e2b59`.
Границы выбранных LEA и invoke calls сверены по полным инструкциям.

1445cb6c0 статически обходит occupied записи контейнера, копирует key / payload,
затем вызывает переданную извне операцию и очищает временные копии. Эта функция
не исполнялась; роль внешнего callback и инициатор перечисления неизвестны.
Её нельзя называть событием обновления настройки только по наличию обхода.

Задание `14990b71689a18e89aee8c35e6b9bcf9e2ddb1e9b304ff314a8ec8eff15493f5`
объединило read / write consumers с четырьмя готовыми roots: 1445c78d0 /
1445c67a0 / 141425d60 / 1445c29f0. Готовые материалы переиспользованы;
дополнительного полного экспорта нет. Exact compare / capture-address /
assignment-forwarding leaves и таблицы сверяются как в прежних replay.

## Подтверждённая цепочка чтения

1445cbd00 получает RCX=output, RDX=key. Временный FString key → native hash →
native lookup в 14b186130 → entry +0x10 (payload). После освобождения временного
ключа читает invoke pointer payload +0x10 и capture storage payload +0x20 либо
inline +0x30. Через table slot +8 получает адрес захвата, затем вызывает
сохранённый invoke с RCX=output / RDX=capture-address.

На строковой привязке invoke 1445c78d0 вызывает настоящий clone 1445c67a0;
он копирует data по сохранённому count, включая terminator / embedded NUL.
Результат — отдельный buffer, исходный destination не меняется. При miss
consumer обнуляет все 16 bytes output и возвращает его указатель.
Found binding обязан иметь корректные active callable objects; invalid state
не проверен, наличие consumer не означает безопасный вызов произвольной записи.

## Подтверждённая цепочка записи

1445d6ec0 получает RCX=key, RDX=new-value pointer. После аналогичного поиска
и освобождения query FString выбирает вторую операцию: invoke payload +0x50,
capture storage payload +0x60 либо inline +0x70. Table slot +8 возвращает
адрес захвата. Invoke получает RCX=capture-address и RDX=адрес локального
указателя на новое значение. Leaf 1445c7970 разыменовывает оба аргумента и
передаёт target FString / new-value data в 1414277b0.

Реализация 1414277b0 здесь fixture, фактическое native присваивание строки ещё
не проверено. Подтверждено направление в правильный destination и передача
нового значения; miss не вызывает invoke. Инициатор этого consumer, условия
доступности, persistence, precedence и источник обновлений остаются неизвестными.

## Проверки

`replay-ui-config-consumers.py` прошёл 96 последовательностей read → write →
read: восемь начальных payloads, inline / external capture storage и шесть
запросов (три ключа, ASCII case variant, non-ASCII case miss и absent key).
Всего 288 полных consumer вызовов: 128 native read invokes и 64 write invokes.
Есть нулевой FString, terminator-only строка, кириллица, surrogate pair, slash,
длинная строка и synthetic embedded NUL; это не контракт допустимых setting keys.

Проверены выбранная запись / capture getter, ABI invoke, read-before / read-after,
нулевой miss result, независимый clone buffer, guard bytes, неизменность остальных
destination / их данных и всего контейнера. После free-query fixture его bytes
помечаются DD: последующая операция использует сохранённый capture, а не query.

Пять services — fixtures: query FString construction, query free, clone allocation,
byte copy, assignment target FString. Native hash / lookup / compare / capture getter /
clone и оба consumer выполняются полностью. Записи подготовлены синтетически
по ранее проверенной структуре; это ещё не общий registration → dispatch replay.
Runtime allocation / ownership / lifetime, active settings и Brush не доказаны.

Unicorn 2.1.4 / Capstone 5.0.6, полный source SHA / unwind / exact leaves /
padding / таблицы проверяются до исполнения. Все тринадцать tests tile refresh
прошли. Результат включён в source-bound план обновления без runtime promotion.

Отчёт вне Git: `code-clues/ui-config-consumers-d00a-01.json`, SHA256
`23078f7f80613754429ceacba6a324eb3b66d90ad148a68df9625867fa19dde0`.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-ui-config-consumers.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/14990b71689a18e89aee8c35e6b9bcf9e2ddb1e9b304ff314a8ec8eff15493f5/manifest.json' --output 'F:/PhoneExit Resources/Vampir/code-clues/ui-config-consumers-d00a-next.json'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_ui_tile_refresh.py -v
```

Далее — native string assignment и общий registration → read/write на одной памяти.
Источник события / caller обоих consumers исследуется отдельно; локальный вызов
не доказывает автоматическое обновление UI или разрешённое действие бота.
