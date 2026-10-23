# Текущий игровой получатель результата SDK SignIn

23 октября 2026. EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [текущего launcher-контракта](HEADLESS-RELEASE-LAUNCHER-CONTRACT.md).
Авторизация, чтение токенов, создание SDK-профиля и игровые действия отсутствуют.

## Статическая цепочка

`0x1444e7630` копирует callback из auth `+0x98`, очищает исходный count
`+0xa0`, сохраняет исходную response shared pair в closure и передаёт descriptor
в `0x141409e10`, selector 1, с function pointer `0x1444dfac0`.
Сам dispatcher не выбирает регистрацию или повторный HTTP-запрос.
Scheduler, привязка делегата и последующий виртуальный вызов здесь не исполнялись.

Обратный поиск от текущего `SignInByLauncher` подтвердил два E8 в
`0x144503d00`. Он сохраняет входной callback по ChannelManager `+0x80`,
а в ветке channel 200 передаёт callback дальше в `0x144504980`.
Wrapper `0x144503c80` копирует входной function descriptor и вызывает этот manager.
Его прямой игровой caller — `0x14561b6a0`, callsite `0x14561b817`.
Caller создаёт descriptor с leaf `0x145608220`; байты `e9dbceffff`
ведут в фактический игровой обработчик `0x145605100`.

Таким образом, для этого прямого пути установлен конкретный callback приложения.
Это не доказательство исполнения всего startup / SDK lifecycle на реальном аккаунте.
Есть отдельный caller manager `0x1444da480`, переключающий несколько SDK-операций.
Его кандидат сначала не прошёл полное локальное декодирование; Ghidra подтвердил
callsite `0x1444da8a8`. Он сохранён отдельно, не принят за основной игровой caller.

## Целый игровой callback

`0x145605100` сначала пытается закрепить weak owner. Нет control block,
strong count равен нулю или owner отсутствует — внешних действий нет.
При живом owner вызывается `0x1456151f0` с той же response pair и byte шага.
Полный статический экспорт этого helper показывает форматирование строк результата
и передачу в журнал `0x14563a5f0`; прямого SignUp в нём не обнаружено.
Журнал и форматирование в replay заменены capture, а не исполняются как движок.

Затем callback различает шаги 14 / 15. Используются настоящие getter leaves:

| Getter | Байты | Поле |
| --- | --- | --- |
| `0x144532750` | `837904000f94c0c3` | predicate `dword +4 == 0` |
| `0x141a2d1b0` | `8b410cc3` | `dword +0xc` |
| `0x14180e6e0` | `488b4128c3` | `qword +0x28` |

Подтверждено исполнением целого callback:

- `+4 == 0`: manager action pointer `0x143b92dd0`; при наличии child `+0x58`
  также capture `0x145615e40`.
- Ненулевой `+4`, `+0xc` равен 40040011 или 30050012, а `+0x28` равен
  429 либо 502: другой manager action pointer `0x144570980`.
- Остальные ошибки: error-text helper `0x145609600`, затем message helper
  `0x14561b2b0`, selector 7 для шага 14 и selector 8 для шага 15.
  Selector записывается через DL; старшие биты RDX не являются его частью.
- Иные шаги 0 / 255: только capture журнала, без этих UI / manager actions.

Для существующего owner count после возврата равен исходному 4.
Случай null owner также возвращает count к исходному; гонки и финальный
destructor при count 1 не покрыты. Отсутствие неожиданных вызовов проверяет
fail-closed hook: неизвестный target останавливает replay.

Всего 64 комбинации: четыре шага × восемь профилей raw result × наличие child.
Дополнительно три owner gate: **67 сценариев**. Значение `+0x28 == 1203`
использовано как synthetic boundary case. Это **не восстановленная структура
живого SDK-отказа 1203**: HTTP error construction и сопоставление raw полей
с конкретным живым ответом здесь не исполнены. Нельзя называть этот replay
доказательством причины серверного отказа.

Новая авторизация, SDK SignUp и создание персонажа из проверенной целой функции
не вызываются. Однако внешние manager / UI captures могут иметь дальнейшие
действия, а выбор первоначального шага и способа входа находится выше.

## Материалы и повторная проверка

[replay-release-game-sign-in-result.py](../../../replay-release-game-sign-in-result.py)
использует существующий bounded harness. Полный SHA EXE, все инструкции
экспортов, SHA материалов, три getter leaf и E9 проверяются до результата.
Граница native execution — целый `0x145605100` и три getter leaves.
Logging, строки, error text, UI, manager / child actions — fixtures / captures.
Caller roots, dispatcher и log helper проверены статически.

Ghidra-пути относительны к
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`:

| Материал | SHA256 |
| --- | --- |
| `details/run-e0b2e7fef500/details.json`, dispatcher | `2542f275a915286ae02709624bfacca4ca7034649104138c2e76abb790a5d794` |
| `details/run-480aabc11edb/details.json`, manager | `6dcb121d9b4f3afcbe19aaed870bc7a59d463613c00ce73a6d35c543498d4e3e` |
| `details/run-bd88fe6b96de/details.json`, wrapper и другой caller | `fdfccac0bee932c873ddf224a86b975e3fea3f2b20ef3a2b33be8e5ab4b35c73` |
| `details/run-122867bb3bc4/details.json`, игровой caller | `7640a2cd9a17d7ff0d76f1a28b735deab08483d24036400ad12adebd2732e159` |
| `details/run-6092fea5749a/details.json`, целый callback | `96ca33af8b1026fe13594afacc28c960ee358c002038cc7a406792a2bfd38fa3` |
| `details/run-1d064761d70c/details.json`, log helper | `c439dba14da9fb7294249dbf53ced371c1307d3b35c55dd0556c4c9bfa10fec3` |

Report:
`F:/PhoneExit Resources/Vampir/code-clues/release-game-sign-in-result/3e64cc5da91b56cf07a56d8144aec4f23f02525f68990dc1e26e5786602a1210/manifest.json`.
SHA256 совпадает с именем каталога. Два теста проверили ветви, lifetime,
статические handoffs и отклонение изменённого export.
Check `release-game-sign-in-result` подключён к launcher-auth-contract.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-release-game-sign-in-result.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_release_game_sign_in_result.py
```

Следующий конкретный участок — выбор операции / channel / step перед
`0x14561b6a0`. Проверены E8 из roots `0x145603ab0` и `0x145605440`;
смысл этих roots ещё не присвоен. Source-bound caller report
`sdk-reference-candidates/a92e6c88aa203d1d43cbaf2d1646ab4b3d733608e7d8132ff3f27dacf76aa6f4/manifest.json`
имеет SHA256 `a92e6c88aa203d1d43cbaf2d1646ab4b3d733608e7d8132ff3f27dacf76aa6f4`.
Начинать с этих двух адресов через prepare; не повторять scheduler, HTTP bodies
или прежние живые входы без нового различающего условия.
