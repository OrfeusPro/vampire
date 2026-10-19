# LoginResult: native handler, result gate и записи состояния

19 октября 2026. Продолжение [body reader](HEADLESS-LOGIN-RESULT-READER.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

Сначала прочитаны Ghidra `LoginResult_Handler.c` и `Result_Gate.c` из
`F:/PhoneExit Resources/Vampir/ghidra/INDEX.md`. Дополнительно экспортирована
функция **0x1467259c0**, аналитическая метка `Login_PostState`.
Текущий пакет: 33 функции, 15 warnings. Export run: `run-ccea83046ea9`.
`functions.json` SHA256:
`da414cd12e97aae64ce356eed057db529762ea37092ed9f49125c23283345ba4`.
Старые immutable exports сохранены; [команды Ghidra](HEADLESS-GHIDRA.md).

[replay-login-result-handler.py](replay-login-result-handler.py) →
`F:/PhoneExit Resources/Vampir/code-clues/login-result-handler-replay.json`.
SHA256: `c00701637d964100a67d4ce5cf74bf26a40990e1a1878189f5e53984f2dde4eb`.
Report сохраняет source/tool/upstream SHA, native fragments/file offsets,
getter leaves, handler table, целые PE ranges gate и реально исполненные
инструкции gate. Inline switch data не выдаются за линейные инструкции.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-login-result-handler.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_login_result_handler.py
```

В каждом из 38 сценариев в одном эмуляторе сначала исполняются actual constructor/
body reader, затем полный handler **0x146765540**. Таблица **0x149d81080**
slot+0x10 заново привязана к handler. Result gate **0x1467a8e10** исполняется
для covered codes с packet ID 4; короткие bodies сюда не допускаются.
Listener/Dispatch/получение реального ответа в этот run не входят.

## Успех и ранний выход

Для covered `code 0` native gate возвращает 1 при обоих проверенных значениях
state getter+8 (0 и 1). Дальше getter **0x144aaa9d0** реально читает
global **0x14b520d90**, а leaf **0x144aaaab0** читает `[wrapper+0x10]+0x2a6`.
В эмуляции wrapper/peer синтетические; настоящий singleton не читается.

Если peer flag ненулевой и signed int16 packet+0x48 положителен,
вызываются helper **0x145d46a70** и virtual exit slot+0x38, затем return.
Оба backend вызова — captures. Основные поля ответа при этом не копируются.
Проверены +0x48=0/1/32767/32768/65535 с peer flag 0/1:
32768 и 65535 — отрицательные signed значения и раннего выхода не вызывают.
Это не подтверждает имя/назначение поля+0x48 или peer flag.

## Перенос полей в объект состояния

Getter **0x145c859f0** — fixture, возвращающий отдельный synthetic state object.
Actual handler instructions записывают:

| Источник packet | Поле state | Проверка |
| --- | --- | --- |
| FString+0x18 | FString+0x28 | Native caller, copy/assign helpers fixtures |
| raw64+0x68 | +0x38 и+0x88 | Actual native stores |
| bool+0xe0 | byte+0xa0 | Actual native store |
| raw64+0xf0 | +0xb0 | Actual native store |
| raw64+0x100 | +0xc0 | Actual native store |
| raw64+0x110 | +0xd0 | Actual native store |
| raw64+0x120 | +0xe0 | Actual native store |
| bool+0x128 | byte+0xe8 | Actual native store |

Unicorn memory-write hook сохраняет instruction address/offset/размер/значение
каждой из 8 native state writes. Эти записи отличаются от host string fixture;
не объявляются userID/token/account без отдельного getter evidence.

Native handler вычисляет
`floor(signed_int16(packet+0x60) * 600000000.0 + 0.5)`
и пишет int64 в **0x14b4f3458**. Константы double с адресами/bytes сохранены.
Проверены raw16=0/1/32768/65535. Единицы и временная шкала не установлены.
В helper **0x1445d1210** передаются raw64+0x58 и raw16+0x60; backend capture.
Clock helper также capture: вычисленная запись здесь опирается на packet field,
а не на измеренное время ОС.

Actual selected-server leaf **0x144aaaa10** читает peer+0x270. Handler сверяет
его с controller+0x30c и при различии записывает ID в+0x30c и+0x308.
При прежнем ID 42 обе записи пропускаются; helper **0x145c0a1b0** всё равно
получает 42. Controller getter и helper/persistence — fixtures/captures.

Положительное signed+0x48 при отсутствии раннего выхода вызывает дополнительный
optional-object helper и вторую state-toggle операцию. Null optional object
пропускает object helper, но не вторую toggle. Capture фиксирует low byte
bool-аргумента, не случайное содержимое старших бит регистра.

## SDK и дальнейшие действия

Global SDK flag **0x14b520cc3**, singleton manager и отдельные manager fields
управляют разными действиями:

- manager+0x88 → virtual callback slot+0x20;
- manager+0xa0 → helper **0x14563bb80**;
- manager+0x38 → FString getter/final helper **0x145636eb0**.

Native conditions и singleton getter leaves исполняются; объекты и callbacks
подставлены тестом. Проверены SDK disabled, manager absent, empty manager,
callbacks без auth, auth без callbacks и все поля вместе. Post predicate
**0x145be5fb0** проверен отдельно; его backend и последствие — captures.
Packet bool+0x138 включает helper **0x1466fd130** только при true.

Успешный основной путь достигает **0x1467259c0** и virtual+0x28 объекта
из getter **0x146486a50**. Оба действия capture. Ghidra export первой функции
показывает поиск/проверки объекта и virtual calls; прямой CharacterListRead
send в разобранном участке не доказан. Метка `Login_PostState` аналитическая.
Не переименовывать эту точку в «запрос персонажей» без дальнейшей цепочки.

## Ошибки

| Raw code | Фактически исполненная ветвь |
| --- | --- |
| 14/22/37 | Gate false → helper 0x14676a270; при 22 native byte 0x14b571319=1 |
| 54 | Отдельный popup path до result gate; backend capture |
| 9400 | Gate false → helper 0x145c8b6b0 с packet+0xc8/+0xb8/+0xa8 |
| 9818/9819 | Отдельная optional-object ветвь до gate; finish helper вызывается и при null |
| 90021 | Отдельный object helper до gate; finish вызывается и при null |
| 1/0xffffffff | Gate false → actual disconnect thunk → backend capture; exit либо popup |

Backend UI/error helpers не исполняются. Message FString+0x38 длиной≥2
включает generic popup вместо exit virtual в covered code 1; длина дескриптора
содержит terminator. При gate state 1/code 1 общий gate-error helper пропускается,
но handler всё равно идёт в failure path. Во всех covered error cases основные
успешные state fields и controller server не обновляются.
Коды означают raw ветви; серверные текстовые названия ошибок не выдумываются.

## Проверки и ограничения

[Четыре tests](../../test_vampir_headless_login_result_handler.py) воспроизводят
38 cases, проверяют source/range SHA и bytes gate trace, все основные stores,
signed comparisons, controller writes, raw16 calculation, SDK gates и error routes.
Смежные LoginResult reader и Ghidra tests пройдены. Полный suite не повторялся.

State/service/controller getters, diagnostics, FString helpers, UI/SDK callbacks,
clock/persistence/disconnect/post-state backends — явные fixtures/captures.
Общий runtime не менялся; события replay не являются готовой state machine бота.
Проверены только указанные gate branches. Другие targets завершают replay ошибкой,
а не исполняются как произвольный неизвестный код.

Не запускались игра/сеть/Android, не читались реальные profile/process memory/
credentials. Native body→handler coverage не доказывает живой login/session.
Следующий участок — действие virtual+0x28 после LoginResult и доказанная цепочка
к запросу списка/выбору персонажа; отдельно остаётся request lifecycle/socket/
свежие SDK и device/profile inputs.
