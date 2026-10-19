# NID storage suffix: sub → bytes → AES → HEX

19 октября 2026. Продолжение [auth path gate](HEADLESS-SDK-AUTH-PATH.md).
Источник — Windows клиентский EXE, SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это не исходный C++ проект. Используются прежние source fragments и hashes,
не данные настоящего аккаунта.

Инструмент `replay-sdk-nid-path-suffix.py`.
Отчёт `F:/PhoneExit Resources/Vampir/code-clues/sdk-nid-path-suffix-replay.json`,
SHA256 `92be8d8f2b35b5bd72f9bcde552e1f229f6daf178ff9397c57afec8d6b34bb2f`.
Содержит decoded caller/AES/formatter/initializer fragments с bytes/file offsets,
SHA и tool SHA; leaf wrapper bytes и SHA прежнего source report.

Дополнение: [native token container и channelKey migration path](HEADLESS-SDK-TOKEN-PAYLOAD.md)
проверены отдельно с явными границами split/JSON/подписи и allocation tail.

## Источники аргументов

SetupServiceSettingPath на `0x14454cb60` проверяет поле global `0x14b4f1a38`,
затем читает его как строку. Initializer `0x1411b31f0` связывает global с **sub**.
На `0x14454cb92` вызывается GetNMDeviceKey `0x1444e5ff0`.
Это именно nmDeviceKey, не SDK deviceKey и не DeviceKeyForNetmarbleId.
Разбор входного токена/получение объекта sub пока остаются статической цепочкой.

Replay начинается **после** этих calls, с явно заданными sub/nmDeviceKey.
Не считать его проверкой JWT, подписей, server identity или настоящего auth context.

## Проверенное native исполнение

Caller `0x14454cb97..0x14454cc9c`:

1. Если длина sub без NUL <32, пропускает замену suffix.
2. Выделяет byte buffer длиной sub; для каждого uint16 берёт младший byte,
   вычитает 1 по модулю 256 и пишет в buffer. Native loop использует wide NUL
   как terminator и отдельный bound по count.
3. Преобразует nmDeviceKey в ANSI и передаёт его как ключ в wrapper `0x141525480`.
4. Wrapper переставляет аргументы и вызывает CPU-dispatch function pointer.
5. Полученные bytes форматируются `%02X` и переносятся в global `0x14b4f1ee0`.

AES-NI dispatch **явно закреплён fixture** на `0x14151ecc0`. Сама key expansion,
AESENC/AESENCLAST обработка выполняется native, а не Python crypto shim.
Исходный dispatcher `0x14150a520` экспортирован статически: CPUID определяет
software/AES-NI branch. CPUID/первый dispatch этим replay не исполнялись.

Actual AES output для synthetic aligned buffers совпал с независимым
**AES-256 ECB encryption** (`cryptography`), без IV, padding или хеширования.
32-символьный ASCII nmDeviceKey используется как 32 bytes ключа, а не как
hex-decoded 16-byte значение. Регистр ключа важен, нормализация изменяет suffix.

Native hex writer `0x141429460` проходит bytes и вызывает `%02X` formatting.
Сам `%02X` formatting и FString append — ограниченные fixtures; loop/control flow
и переданные значения native. Wide-to-ANSI key conversion, allocation/free —
fixtures. Их native source также сохранён для последующей проверки.

## Шесть synthetic cases

- Пустой sub и длина31: сохраняют `old-suffix-fixture`, crypto не вызывается.
- Длины32/48/64 с одинаковыми символами и known fixture key: совпадают с
  независимой ECB моделью. Повторные блоки дают повторные encrypted blocks.
- Другая 32-byte строка и другой key: отдельный совпадающий результат.

Все исходные значения искусственные. Невыровненные длины, non-ASCII sub/key,
встроенные NUL, ошибочные object/count и не-32-byte ключи этим replay не доказаны.
Не выводить из минимального caller length check безопасность этих областей.

## Общая реализация

[nid_storage_path.py](../../vampir-shared/vampir_core/nid_storage_path.py):
`derive_nid_storage_suffix(subject=..., nm_device_key=...)`.
Только offline derivation, без сети, токен-парсинга, выбора аккаунта или I/O.
Local policy ограничивает subject printable ASCII, длиной32..1024 и кратностью16;
nmDeviceKey — ровно32 ASCII HEX characters с сохранением регистра.
Более широкий native input domain отвергается, а не молча дополняется padding.
Опциональный cryptography backend уже используется в проекте; Windows проверен,
Android backend пока не проверен. Это воспроизведение хранения клиента, не выбор
криптографии для нового защищённого хранилища бота.

## Границы и далее

Suffix относится к расположению клиентского сохранения и не является ключом
входа/доказательством привязки устройства. Нельзя заменять им отдельные identity
поля [реестра бота](../../vampir-headless/DEVICES.md).
Реальные keys, command line, auth tokens, registry, Saved и процессы не читались.

Далее: исходный token/object/sub parsing и migration branch, source согласование
suffix/active path с Save/Load. Затем сериализация сохранений и SDK sign-in
response/session. Основная почта пока не авторизована, реальные ключи пустые.

Проверки `test_vampir_headless_sdk_nid_suffix.py`: source report reproducibility,
independent AES compare, common runtime/native agreement, strict boundary и
зависимость от регистра ключа. Полный файл/подпись токена не проверяются.
