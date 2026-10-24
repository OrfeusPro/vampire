# LoginResult 1.13.16: native handler и covered result gate

Источник — EXE SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Связь ID 4 с текущим handler установлена ранее через
[регистрацию](HEADLESS-LOGIN-RESULT-REGISTRATION-11316.md).
Новый [контекст](../../native-contexts/login-result-handler-11316.json)
исполняет два явных roots: handler `14679aec0`, gate `1467cd7b0`.

## Материалы и границы исполнения

Handler export `run-83255b6c29bc` использован повторно; gate выгружен отдельно
в `run-eff5f37ca91c`, без обхода callees. Полные SHA exports, call sites,
fixture bindings и globals сохранены в контексте. Instructions сверяются с
EXE. Необъявленный target или неподдержанный fixture завершают replay ошибкой;
fixtures не могут заменить handler/gate/ID getter.

В этом прогоне пакет синтетический: поля, строки и ID 4 table заданы явно.
Reader здесь не исполняется. Его [отдельная проверка](HEADLESS-LOGIN-RESULT-BUFFER-11316.md)
не выдаётся за общую body → handler интеграцию. Services/getters, string storage,
UI/SDK/clock/persistence/disconnect/post-state backends — fixtures/captures.
Реальные globals читаются только из immutable EXE snapshot в эмуляторе;
SDK flag, derived value и error flag задаются в synthetic памяти, не в игре.

## 38 сценариев

Для code 0 covered gate возвращает 1 при gate-state 0 и 1. Проверены signed
int16 `packet+48` 0/1/32767/32768/65535 и peer flag 0/1. Peer true вместе с
положительным signed значением вызывает early helper и exit virtual; основные
state поля не копируются. 32768/65535 отрицательны и этого выхода не вызывают.

Основной путь содержит восемь native stores в synthetic state:

| Packet | State | Размер |
| --- | --- | --- |
| `+68` | `+38`, `+88` | 8 bytes каждый |
| `+e0` | `+a0` | 1 byte |
| `+f0` / `+100` / `+110` / `+120` | `+b0` / `+c0` / `+d0` / `+e0` | 8 bytes |
| `+128` | `+e8` | 1 byte |

Каждая native запись сохраняет instruction address, размер и значение.
FString `packet+18 → state+28` копируется storage fixture, отдельно от этих
восьми stores. Полям не присваиваются имена token/userID без других доказательств.

Native calculation пишет в `14b564700`
`floor(signed_int16(packet+60) * 600000000.0 + 0.5)`.
Проверены raw16 0/1/32768/65535. Единицы и временная шкала не установлены.
Controller `+308/+30c` получают synthetic selected server 42, если старое значение
7; при прежнем 42 эти записи отсутствуют, helper всё равно вызывается.

Проверены SDK disabled, manager absent/empty, callbacks/auth отдельно и вместе,
post predicate, optional object absent и flag `+138` 0/1. Handler достигает
post-state capture и view virtual `+28`; это ещё не CharacterListRead.

| Code | Covered path |
| --- | --- |
| 14/22/37 | Gate false, dedicated error; при 22 byte `14b5e2338` становится 1 |
| 54 | Popup capture до gate |
| 9400 | Gate false, отдельный error-fields capture |
| 9818/9819/90021 | Optional object path до gate; finish и при null |
| 1/FFFFFFFF | Gate false, disconnect capture, затем exit либо popup по длине message |

При gate-state 1/code 1 gate-error backend пропускается, но handler сохраняет
ветвь отказа. Во всех covered error/early cases основные state/controller stores
отсутствуют. Проверены packet immutability, object canaries, stack и восемь
nonvolatile GPR. Коды — raw ветви, серверные названия ошибок не выдумываются.

## Препятствие следующего участка

Попытка `run-aaeae96c7f8b` включала post-state `146755540` и gate. Collector
остановился на post-state: `Decompiler block outside requested unwind ranges`.
Она не дала готового export и не повторялась с теми же входами. Логи сохранены;
gate затем получен отдельным явным заданием. Нельзя расширять разрешённое
исполнение до блока декомпилятора без выяснения source/unwind/branch связи.

Post-state остаётся ручной задачей: сверить фактический внешний branch/block
с PE unwind и решить, отдельный ли это callee/fragment. Параллельно требуется
общая body-reader → handler интеграция и реальные singleton/getter boundaries.

## Автоматизация

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_login_result_handler_context.py
```

Три теста прошли за 7,666 секунды: 38 сценариев со stores/ABI/branches, отказ при
подмене gate call/export и запрет заменить native root fixture. Check
`native-login-result-handler-context` подключён к game-login/update, полный SHA,
tools/runtime/context и два exports входят в зависимости. Новый SHA требует
review handler registration/gate call/fixtures/data links и переноса checks;
автоматического runtime promotion нет.

Не проверены остальные gate codes/UI branches, действительный dispatch,
ownership services/storage, real post-state, список персонажей и серверная сессия.
Не запускались игра, авторизация и сеть. Рабочие пресеты, аккаунты, baseline,
строгий decoder и source guard не менялись.
