# NID integer/channel helpers и общий валидатор полей

19 октября 2026. Продолжение [OnResult validation](HEADLESS-NID-VALIDATION.md).
Реальные integer/channel helpers заменили return fixtures в шести новых
интеграционных прогонах caller slice. Отдельно исполнены 28 numeric и 45 channel
fixtures. `mailUserKey` подтверждён как channel 20, ASCII-регистр не важен.

## Источник и воспроизведение

[replay-nid-result-primitives.py](replay-nid-result-primitives.py) проверяет EXE SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это compiled Windows client, не настоящий исходный C++ проект.
Отчёт `F:/PhoneExit Resources/Vampir/code-clues/nid-result-primitives.json`, SHA256
`e7f5864cc0ef76f901126eb2fb2469d1e5de471d42414f539894c2ed08b5323e`.
Сохранены helper/init fragments, byte offsets/bytes/SHA, 13 initializer bindings,
PE import descriptor/thunk/name bytes, compare leaf и таблица, inputs/results.

Команда: `python -X utf8 phone-exit/bots/resource-tools/vampir/replay-nid-result-primitives.py`.
Unicorn 2.1.4/Capstone 5.0.6, instruction budget 16384 на helper call.
Actual native: parser 0x1415dea40, mapper 0x14452b060, compare 0x1414596e0..0x141459727,
13 compiled initializers и прежний OnResult slice/copy в integration.
Initializer FString allocation/construction, atexit/free остаются явными shims.
Map/hash/settings caller dependencies прежние; callbacks не исполняются.

## Числовой parser и CRT

Таблица импортов проверяется existing import_at из build-object-zero-init-code.py:

| Call site | Import |
|---|---|
| 0x1415dea6c | api-ms-win-crt-convert-l1-1-0.dll!_wtoi |
| 0x1415dea7f | api-ms-win-crt-math-l1-1-0.dll!_finite |
| 0x1415deab2 / 0x1415deaea | api-ms-win-crt-string-l1-1-0.dll!iswspace |

IAT calls из эмулятора направлены в настоящие функции загруженного локального
`C:/WINDOWS/System32/ucrtbase.dll`, SHA256
`dedb7611e1abc1ff3852dcac3d4c93a048d729e25b061973b9969f22698f14ca`.
Locale не меняется; результат относится к этой Windows/CRT, Android parity нет.
Полные integer helper instructions исполнены; CRT не заменён int()/isdigit().
Guards вокруг integer output сохранены во всех 28 fixtures.

Наблюдения: пустая строка/abc дают ok=false, 0/00/+0/-0/пробелы и 0.0 дают
ok=true,value=0. Также принимаются 0abc, 00abc, 0x10, 0e9, 0.1 и другие
prefix cases из отчёта. 1abc даёт value=1; 2147483648 насыщается до 2147483647,
-2147483649 до -2147483648. Это конкретные fixtures, не исчерпывающая модель
чисел, локалей или всех Unicode whitespace.

Шесть integration fixtures: 0/mailUserKey достигает adoption captures;
200/mailUserKey и abc/mailUserKey отклоняются; 0abc/MAILUSERKEY достигает
captures; 0/unknown и 0/mailUserKey с trailing space отклоняются mapper gate.
Здесь integer/channel return fixtures удалены, исполняются реальные helpers.

## Каналы

Globals связаны с compiled LEA source → LEA destination → FString constructor.
Compare leaf использует сохранённую 128-byte ASCII table; сравнение non-ASCII
в mismatch branch идёт по исходным units. Native mapper потребляет временный
FString и вызывает free (в replay capture). Output byte guards проверены.

| Ключ из initializer | Channel byte |
|---|---:|
| facebookKey | 1 |
| googleKey | 5 |
| gameCenterKey | 6 |
| twitterKey | 12 |
| mailUserKey | 20 |
| signInWithAppleKey | 26 |
| googleIdKey | 29 |
| steamKey | 30 |
| epicKey | 31 |
| playStationKey | 32 |
| netmarbleKey | 33 |
| xboxKey | 34 |
| guest | 100 |

Все 13 ключей, uppercase и swapcase проверены native. Empty/unknown/email,
leading/trailing spaces и один mixed non-ASCII mismatch дают 0. Не заявляется
полная Unicode case folding или автоматический trim.

## Общий переносимый модуль

`vampir_core.nid_result.channel_key_to_sdk_type` повторяет mapper для printable
ASCII ≤128 chars. Unknown/empty →0; non-ASCII/controls/non-string/oversize →
ValueError по локальной политике. Нет I/O, SDK или Windows dependency.

`validate_nid_email_result_fields` принимает **уже декодированный dict**, не URL.
Проверяет наличие всех шести lookup keys, channel=20, непустые accessToken/ID,
двухбуквенный uppercase country. RefreshToken может быть пустым. Optional
easyLoginToken/issueType проверяются и отбрасываются; unknown keys отклоняются.
Локальные бюджеты: ≤8192 ASCII chars/value, ≤32768 суммарно.

Результат NidEmailCredential — frozen slots dataclass; token/ID/country скрыты
в repr. Это provider credentials, не SDK/game session. Password не хранится.
Для resultCode принимается только точная строка "0": **явно более строгая
локальная политика**, чем native parser. 0abc/00/+0 не принимаются как success.
Country format и printable ASCII также локальные ограничения; неизвестные
форматы не объявляются доказанными ошибками сервера.

Четыре теста проверяют native replay, numeric/caller gates, общую channel table
по ASCII fixtures, field boundary/redaction/missing/invalid inputs. URL/query
percent-decoding, origin/context binding, token storage/expiry/persistence,
settings setters, callbacks и получение игровой сессии ещё не выполнены.
