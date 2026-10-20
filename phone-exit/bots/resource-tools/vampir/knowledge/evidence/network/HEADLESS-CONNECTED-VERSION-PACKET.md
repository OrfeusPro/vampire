# Первый пакет connected callback — PktVersion

19 октября 2026. Продолжение [connection delegate](HEADLESS-TRANSPORT-CONNECTED-DELEGATE.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Источники и воспроизведение

[replay-connected-version-packet.py](../../../replay-connected-version-packet.py) →
`F:/PhoneExit Resources/Vampir/code-clues/connected-version-packet-replay.json`.
SHA256: `8e550d80e6d37bdc5872073c15ea48abf6f65ac14479683ee633f15f51596d57`.
Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-connected-version-packet.py`.
Capstone 5.0.6 / Unicorn 2.1.4. Report хранит source/tool/upstream SHA,
code fragments/file offsets/bytes, packet vtable, name string, ID getter,
wrapper table и результаты шести сценариев.

## Идентификация пакета

Game callback **0x1467a9cd0** действительно вызывает constructor
**0x1456d53b0** на **0x1467a9ddc**. Constructor загружает vtable
**0x1498d6990** на 0x1456d53b6 и сохраняет её в [this] на 0x1456d53c0.
Таблица имеет writer slot+0x10 → **0x1456e5cf0**, ID slot+0x28 →
**0x141448600**, name slot+0x38 → **0x1456e3a10**.

ID getter имеет bytes `b801000000c3` (MOV EAX1; RET), здесь проверены bytes,
не отдельное native execution getter. Name body ссылается на ASCII строку
**PktVersion** по **0x1498d69e0**; строка и instruction-boundary reference
сохранены в report. Поэтому этот первый созданный пакет — **PktVersion/ID1**,
а не PktLogin/ID3 из [packet bindings](HEADLESS-PACKET-BINDINGS.md).
Это важное промежуточное звено, не доказательство всего handshake.

Callback и constructor теперь исполняются после реальной цепочки delegate
из предыдущего replay. Сам send target **0x1467aaa10** остаётся capture:
его связь подтверждена wrapper table 0x149d84e50 slot+0x38 и call site
**0x1467a9fc4**. Writer, frame encoding и Winsock send не исполнялись.

## Raw поля до отправки

Packet constructor обнуляет поля, вызывает FString constructor для поля+0xb0
с char pointer из global **0x14b14ae28** и читает DWORD global
**0x14b125530** в +0xc0. Callback позднее ещё раз заполняет эти поля.
Globals в replay явно заменены fixtures. Даже имя version_ascii в tool —
название test input, а не доказанный getter версии установленной игры.

| Packet offset | Подтверждённый источник в callback | Граница проверки |
| --- | --- | --- |
| +0x10 | FString global 0x14b520d10 / count 0x14b520d18 | Fixture global, native copy |
| +0x20 | Constructor zero | Raw DWORD0 |
| +0x28 | Результат string helpers0x141426250/0x141426180 | Helpers выдают явный combined fixture |
| +0x38 | Getter 0x1414476a0 | Getter fixture, native copy |
| +0x48 | Getter 0x1445c63a0 → copy0x14143c260 | Getter и copy fixtures |
| +0x58 | Входной FString connected callback | Пустой из прежнего endpoint getter fixture |
| +0x68/+0x78/+0x88/+0xa0 | Zero/empty в покрытом path | Нет утверждения о других branches |
| +0x98 | Store на 0x1467a9f78 | Raw DWORD207 (0xcf), семантика не установлена |
| +0xb0 | Char pointer global 0x14b14ae28 → FString | ASCII constructor fixture |
| +0xc0 | DWORD global 0x14b125530 | Native copy fixture enum, смысл unknown |

Не присваивать этим строкам имена userID/token/deviceID/country по offsets
или test values. Например provider_text — лишь имя fixture getter output.
Ни одно значение реального SDK профиля не использовано.

Callback читает context selector через 0x1445c77a0, затем context store через
0x1445bdfe0. В replay selector fixture7, store fixture null: покрыт только
absent-store branch. Present-store path с 0x1416d7af0 не исполнен.
Комбинирование строк, исходные getters и конверсия — fixtures; общий codec
или семантическая модель PktVersion по ним пока не реализованы.

FString allocation/memcpy ограничены размерами; native callback исполняет
ветви пустых и непустых копий, а backend string resize/copy/cleanup fixtures.
Unicode scenario проверяет перенос заданных UTF-16 строк, не общую корректность
локализации или кодировку wire payload.

## Проверки и границы

Шесть native scenarios: version-default, empty-fields, unicode-fields,
send-false, raw-enum-max, delegate-disabled. При default packet поля
содержат ровно fixture inputs; все raw offsets фиксируются до cleanup.
Wrapper+0x160 обнуляется при входе в callback. При отключённом delegate
callback не запускается, packet не создаётся, sentinel wrapper+0x160 сохраняется.

[Три regression tests](../../../../../test_vampir_headless_connected_version_packet.py)
проверяют воспроизводимость/source/table/name/ID/send bindings, точные raw
поля, zero/Unicode/max DWORD cases и gate. При fixture send=false callback
всё равно проходит cleanup, delegate bridge возвращает AL1. Это не recovery
policy и не успех обмена: send body и серверный ответ не исполнены.
Три новых и шесть смежных tests delegate/notification прошли.

Inherited syscall/scheduler/snapshot/endpoint/lifetime fixtures сохранены.
Нет real socket/version negotiation, server response, Login, Android parity
или действующей сессии. Runtime не менялся; полного suite не было.
Игра не запускалась; profile/process memory/credentials/network не использованы.

Далее actual send0x1467aaa10 → PktVersion writer/encoding и VersionResult
handler → последующий Login. Отдельно восстановить реальные getters и значения
полей, особенно входы, которые меняются при еженедельном обновлении игры.
