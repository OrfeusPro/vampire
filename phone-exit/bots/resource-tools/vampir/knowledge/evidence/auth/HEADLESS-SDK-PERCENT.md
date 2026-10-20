# Callback query: native percent loop и строгая общая граница

19 октября 2026. Продолжение [NID primitives](HEADLESS-NID-PRIMITIVES.md).
147 fixtures исполнили percent byte loop и native strlen. Плюс не становится
пробелом; decode выполняется один раз. Общий модуль добавляет строгий ASCII
subset и callback route policy. Полная совместимость URI/parser/map ещё не доказана.

## Источник и воспроизведение

[replay-sdk-percent-decode.py](../../../replay-sdk-percent-decode.py) проверяет полный EXE SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это скомпилированный Windows клиент, не исходный C++ проект.
Отчёт `F:/PhoneExit Resources/Vampir/code-clues/sdk-percent-decode-replay.json`, SHA256
`1b376b2821636664619248be47e215a2488f29054efd00be934ac90505c15e5f`.
Сохранены полные fragments decoder/getter/URI constructor/query-map функции,
byte offsets/bytes/SHA и inputs/output bytes/native strlen/output guards.

Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-sdk-percent-decode.py`.
Unicorn 2.1.4/Capstone 5.0.6. Entry 0x141c13495, stop 0x141c13764, budget 65536.
Выполняются настоящие loop/hex branches, append terminator и strlen.
UTF8 input buffer и output arena/capacity заданы fixtures. Предварительная
UTF16→UTF8 и финальная UTF8→UTF16 конверсия не исполняются. Для двух %u fixtures
conversion 0x141440ac0 заменён явным Python UTF8 shim; hex arithmetic native.
Bounded memcpy — shim; capacity 4096 исключает growth path. Внешней сети нет.

## Связь с callback: пока статическая

OnDeepLink 0x1450ed4f0 вызывает URI constructor 0x1445123b0. Query getter
0x1445255e0 читает descriptor owner+0x58/+0x60 и вызывает decoder 0x141c13390
на 0x144525616. Затем query передаётся в OnResult, который вызывает
map builder 0x144591880 на 0x1450ee871.

Map builder передаёт `&` в 0x14142c810 на 0x1445918f2, затем `=` в split helper
0x141432ba0 на 0x144591966. Native map construction, duplicate handling и
весь URI constructor здесь не исполнялись. Constructor отдельно создаёт
query map с decoded values; это не доказательство, что OnResult использует её:
наблюдаемый caller заново разбирает результат query getter.

Это объясняет границу: сначала decode whole query, затем split. `%26` может
стать разделителем. Нельзя заменять эту цепочку generic parse_qs/unquote_plus
и объявлять результат побайтно совместимым без проверки.

## Наблюдения byte loop

| Input | Output bytes / граница |
|---|---|
| a+b | a+b |
| %2B | + |
| %20 | space |
| a%26b%3Dc | a&b=c |
| %2526 | %26, без второго decode |
| % | пусто |
| %2 | 2 |
| %GG | NUL |
| %G1 / %1G | 01 / 10 hex |
| before%00after | bytes содержат NUL; strlen видит только before |
| %u0041 | A, с явным conversion shim |
| %u20AC | e282ac, с явным conversion shim |

Дополнительно исполнены empty, plain ASCII, 1024-byte input и все %00..%7F.
Выходные guards сохранены во всех 147 fixtures. Эти результаты не доказывают
обработку всех Unicode/invalid UTF8/surrogates в полном decoder.

## Общие функции и локальная политика

`vampir_core.sdk_percent.decode_sdk_percent_ascii` принимает ≤32768 printable
ASCII chars, декодирует только корректные %HH один раз, оставляет + как +.
Decoded controls/DEL/non-ASCII, malformed escapes и %u отклоняются. Это явно
более строгая политика, чем native truncation/invalid-nibble handling.

`vampir_core.nid_result.parse_nid_email_callback(url, expected_game_code=...)`:

- Явная game scope: схема nm{gameCode}, exact authority nmidprovider, /result.
- URL ≤32768 printable ASCII без literal spaces/backslash/fragment; port/userinfo
  и другие routes отклоняются. Game code ≤64 lowercase ASCII letters/digits/hyphen.
- Whole-query strict percent decode → split & / first = по локальной политике.
  Не больше восьми полей, duplicates/malformed/unknown fields отклоняются.
- %26 в исходном query отвергается до decode как неоднозначный separator,
  включая попытку внедрить известное optional поле в значение токена.
- Existing validate_nid_email_result_fields проверяет canonical0/email20/presence,
  country и budgets; результат — redacted NidEmailCredential.

Encoded ampersand отклоняется, а не молча меняет значение токена или поля.
Encoded %2526 остаётся literal %26.
Encoded = остаётся частью value после первого separator. Percent-encoded #
декодируется внутри query value; literal # в URL отвергается как fragment.

Это **local callback boundary**, не полная модель native URI/map. Exact route,
duplicate rejection, canonical success и ASCII limits — локальные правила.
Expected game code не доказывает active SDK configuration. Callback URL не
проверяет nonce/signature/browser provenance/server token validity или наличие
активной попытки входа. Нет I/O, token storage, SDK mutation, callbacks или game session.

Четыре теста проверяют native reproduction/byte boundaries, printable ASCII
subset, scoped callback→credential, single decode/+ handling, duplicate/malformed/
insecure routes и secret-safe errors. Далее full query/map semantics, привязка
к активной попытке входа, settings/persistence и post-adoption SDK callback.
