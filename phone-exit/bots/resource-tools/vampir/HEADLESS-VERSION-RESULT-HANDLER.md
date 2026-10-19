# VersionResult: reader, Dispatch и переход к Login routine

19 октября 2026. Продолжение [Version send path](HEADLESS-VERSION-SEND-PATH.md)
и [Dispatch](HEADLESS-DISPATCH.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

[replay-version-result-handler.py](replay-version-result-handler.py) →
`F:/PhoneExit Resources/Vampir/code-clues/version-result-handler-replay.json`.
SHA256: `3ff60bb50a5c5db435537728fa2a9f90d166f89303d78fdada13042b1bc377df`.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-version-result-handler.py`.
Capstone 5.0.6 / Unicorn 2.1.4. Report хранит source/tool/upstream SHA,
SHA исходного packet-bindings report и выбранную запись PktLogin,
fragments/file offsets/bytes, bounded ctor/ID/gate spans, две vtables,
name string и 39 native scenarios.

## Source bindings

ASCII **PktVersionResult** по **0x1498d6a40** → name getter **0x1456e3a40**
через LEA на 0x1456e3a49. Packet vtable **0x1498d69f0**:
reader slot+0x20 → **0x1456d9b10**, ID slot+0x28 → **0x141484e40**
(actual MOV EAX2; RET), name slot+0x38 → getter выше.
Bounded constructor **0x1456d5460..0x1456d5488** устанавливает эту table в [this].

Factory **0x14678ec40** на **0x14678ec9c** вызывает именно constructor,
а **0x14678ecaf** регистрирует packet/handler через **0x1467a7250**.
LEA **0x14678ec7b** задаёт handler table **0x149d81170**:
slot+8 → actual wrapper **0x141535f20**, slot+0x10 → **0x146768360**.
Эти связи статические и перепроверяются по инструкциям. Полная factory
не исполняется; replay выдаёт synthetic registry ID2/packet/handler.

## Native reader: тело 17 bytes

| Packet field | Wire offset | Тип и archive slot |
| --- | --- | --- |
| +0x10 | 0 | 4 bytes, slot+0x58 |
| +0x14 | 4 | 4 bytes, slot+0x60 |
| +0x18 | 8 | 1 byte → bool, slot+0x88 |
| +0x1c | 9 | 4 bytes, slot+0x60 |
| +0x20 | 13 | 4 bytes, slot+0x60 |

Read table **0x14961a520** slots+0x58/+0x60 используют **0x144aa59c0**,
slot+0x88 → **0x144aa5c10**. Actual reader/native archive IO исполняются
с swap0; DWORD little-endian, значения фиксируются как unsigned bit patterns.
Bool reader нормализует любой ненулевой input byte в 1 (проверены 0/1/2/255).
Названия остальных fields/enum semantics пока unknown.

Для всех 17 коротких prefix lengths0..16 reader=false, OnHandler не вызывается.
Полное тело с extra bytes принимается: exact body exhaustion не проверяется
этим native path. Это не основание допускать произвольный мусор в будущем API.
Неизвестные IDs0/1/3/17/65535 не вызывают reader/handler найденной записи.

## Handler и настоящий result gate

Dispatcher исполняет actual constructor/reader, ставит active packet/TLS,
через virtual wrapper входит в **0x146768360**. В отличие от прежнего Ping
replay тело handler исполняется. Formatting/diagnostic helpers — fixtures.

Handler вызывает packet ID getter, передаёт первое поле packet+0x10 как ECX,
ID2 как EDX, временный нулевой struct и raw R9D0 в **0x1467a8e10**.
Новый replay исполняет **bounded head0x1467a8e10..0x1467a8e9d** и
**tail0x1467a91d6..0x1467a9226** этого helper для выбранных ветвей.
Его общий unwind range включает switch data и не декодируется целиком;
не выдаём данные таблицы за инструкции и не заявляем полное исследование helper.

Getter **0x14558edf0** возвращает synthetic state object с byte+8 = fixture0/1.
При flag 1 код сразу различает нулевой/ненулевой result. При flag 0 исследованы
codes0/1/42/708/1304/0xffffffff. В этих paths **только code 0 возвращает AL1**.
Code42 даёт false без error helper. Codes1/708/1304/0xffffffff при flag 0
вызывают **0x145f8a7a0(code,0)**, затем false; при flag 1 этот call пропускается.
Error helper capture, его UI/policy effects не исполнялись. Другие codes,
ветви и семантика state getter остаются открытыми; не обобщать выбранные cases
на все error policies игры.

## Переход к подготовке Login

Если gate=true, handler на **0x146768460** вызывает getter **0x144aaa9d0**
(fixture), а на **0x146768468** — **0x1467a9700** с его result как this.
Вход в эту routine теперь достигнут native chain и захвачен.

Её static fragment содержит call **0x1467a97fd → 0x1456d4c80**,
который [packet bindings](HEADLESS-PACKET-BINDINGS.md) связывают с constructor
**PktLogin**, vtable0x1498d6058/ID3. Выбранная запись и SHA report включены
в новый результат. Поэтому определён следующий конкретный участок Login,
но **тело 0x1467a9700 и сам Login constructor этим replay не исполнялись**.
Нет доказательства заполнения, отправки или принятия Login сервером.

## Проверки и границы

39 scenarios: 6 result codes ×2 state flags, 4 bool byte values, extra-body
case, 17 коротких тел, 5 неизвестных ID.
[Три regression tests](../../test_vampir_headless_version_result_handler.py)
перестраивают report, проверяют source/table/registration/Login constructor
bindings, decoded values, gate input ID2 и native return, точные error/success
routes, bool normalization и short/unknown gates.
Три новых и семь смежных tests send-path/Dispatch прошли.

Actual TLS reset, active packet clear, archive destructor и return выполняются
после каждого сценария. Короткая reader-failure diagnostic ветвь пропускается
так же, как в предыдущем Dispatch replay; native cleanup сохраняется.
Registry/TLS/snapshot lifecycle остаются fixtures из прежнего harness.

Receive-A используется как изолированный вход в Dispatch; это не доказательство,
что live game использует A вместо B. CRC validation и реальная Version
negotiation не проверялись. Runtime не менялся; полный suite379 не повторялся.
Нет game launch/profile/process memory/credentials/network/Android execution.

Далее **0x1467a9700**: исполнить Login constructor и восстановить источники полей,
SDK token/player/device inputs, writer/frame/send и серверный LoginResult.
Также остаются actual queue drain/socket и weekly Version input sources.
