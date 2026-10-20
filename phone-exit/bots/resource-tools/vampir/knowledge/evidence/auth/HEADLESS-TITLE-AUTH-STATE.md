# Title auth-success: country/state slices и BeginGame gate

19 октября 2026. Продолжение [title notification](HEADLESS-TITLE-AUTH-NOTIFICATION.md)
и [entry ветвей](../interface/NATIVE-ENTRY.md).
Источник — собранный Windows клиент, не исходный C++ проект.
EXE SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.

## Воспроизведение и точная область исполнения

[replay-title-auth-state.py](../../../replay-title-auth-state.py) →
`F:/PhoneExit Resources/Vampir/code-clues/title-auth-state-replay.json`.
SHA256: `e44014173d95c14151a024d17bf2c3984cd830baf619b1642f3e97041b411fce`.
Report сохраняет source/tool/entry-report SHA, instruction bytes/file offsets,
полные fragments и literal provenance. Команда:
`python -X utf8 phone-exit/bots/resource-tools/vampir/replay-title-auth-state.py`.
Capstone 5.0.6/Unicorn 2.1.4, budget head/tail по 2048, gate 1024 instructions.

Это **две отдельные исследовательские части** title handler:
0x14641d560..0x14641d70a и 0x14641dac5..return.
Средняя часть, включая country blacklist, subsystem/UI/state branches,
**пропущена явным fixture jump**, не выдана за исполненный непрерывный путь.
Tail выполняется только если head прошёл manager/auth-service guards.
Это не доказывает, что любой живой клиент обязательно достигнет tail.

Отдельно исполняется call/test/branch 0x14641809c..0x1464180a9
из встроенной BeginGame ветви, реальный wrapper 0x145609b00 и реальный
UNMServiceSettings::IsSignIn 0x14452afb0. Остановка перед следующим действием:
PASS 0x1464181bc, FAIL 0x1464180a9. Предыдущие условия кнопки и последующий
BeginGameImpl 0x146425730 не исполняются.

## Что делает проверенный title handler

Head возвращается без этих действий при null manager либо manager+0x38.
При живых fixtures он получает country string через wrapper 0x1456041d0
и передаёт её setter 0x14556d5f0. Getters/setter здесь captures;
их source bodies сохранены статически. Wrapper вызывает settings GetCountryCode
0x144522160; setter содержит literal ConnectCountryCode.
Не смешивать это с player.joinedCountryCode или выбирать сервер по country
без отдельного доказательства.

Tail действительно записывает byte 1 в interface+0x230
(0x14641dac5). Title interface расположен по object+0xa18, то есть для
полного title object это offset+0xc48. В документации он назван title flag
по месту записи; его UI-смысл и все consumers пока не доказаны.
Tail также вызывает другие post-action функции; они captures.
Проверенный tail не записывает SDK settings+0x400.

## Как проверка BeginGame читает SDK flag

Wrapper 0x145609b00 получает settings CDO через class+0x110, затем
переходит JMP в 0x14452afb0. Diagnostic последнего —
UNMServiceSettings::IsSignIn. Реальный native getter читает byte settings+0x400.
Call site проверяет AL и при ненулевом значении ведёт к BeginGameImpl call site.
Title flag interface+0x230 эта конкретная проверка не читает.

Связь с [SDK completion](HEADLESS-SDK-SIGN-IN-COMPLETION.md): native SetSignIn
записывает тот же SDK offset+0x400. Ранее показано, что этот флаг может быть
true при неполных данных ответа; BeginGame gate этим не превращается
в полноценную проверку origin/token/player/expiry или серверной сессии.

## Десять сценариев и выводы

Для SDK flag false/true проверены country empty/UA/KR, null manager и null
auth service. Country getter возвращает fixture strings, setter захватывает
их без изменения, в том числе пустую строку. При пройденном head и явном
skip-middle tail ставит title flag. SDK flag остаётся прежним.
Отдельная gate-проверка следует только заданному SDK flag.

Есть fixtures title flag=1/SDK flag=0 и title flag=0/SDK flag=1.
Они доказывают независимость этих **исследованных slices**, а не допустимость
всех таких комбинаций в живом клиенте. Сценарий null manager/SDK flag=true
не утверждает, что полная кнопка игры проходит прежние manager guards:
isolated gate стартует после них.

Settings CDO, context, country/player getters, форматирование и post actions —
fixtures/captures. Реальная UI-visible геометрия, blacklist, subsystem policy,
active account state и кнопки не проверялись. Никаких UI-кликов нет.
Игра не запускалась; память процесса, Saved/profile, credentials и HTTP не использованы.

[Три regression tests](../../../../../test_vampir_headless_title_auth_state.py)
проверяют source offsets/calls/diagnostics, guards/country transfer,
отдельность flags и факт skip-middle. Шесть смежных tests прошли.
Runtime не менялся; полный suite 316 из runtime milestone не повторялся.

Далее BeginGameImpl 0x146425730: server selection и соединение с существующими
packet Login схемами. Среднюю часть title handler сохранять отдельной UI/policy
зависимостью; headless login не считать готовым по одним клиентским флагам.
