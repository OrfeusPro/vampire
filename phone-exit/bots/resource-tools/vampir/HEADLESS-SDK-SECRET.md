# Vampir — Base64 и параметры RSA секретных констант

19 октября 2026. Продолжение [разбора ответа GMC2](HEADLESS-SDK-UNESCAPE.md).
H04b частично: общий Base64-декодер добавлен, полное RSA-расшифрование
и получение действительной конфигурации ещё не реализованы.
Продолжение: [исполнение OAEP и общий декодер одного chunk](HEADLESS-SDK-OAEP.md).
Там уточнены PEM-формат и диагностические имена, пропущенные прежним обзором.

## Источник и воспроизведение

Собранный Windows клиент:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
VA относятся к image base `0x140000000`; версия выпуска игры и соответствие
Android не установлены. Строка EXE `OpenSSL 1.1.1t  7 Feb 2023` относится
к библиотеке, а не к версии игры.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-sdk-secret.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_sdk_secret.py -v
```

Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-sdk-secret.json`, SHA256
`7467d8fd1507ef093a10a693f5942e971729df9a07a276815d9d2eea67ae011f`.
Сохранены хеши исходника/инструмента/фрагментов, инструкции, таблицы, литералы,
смещения и искусственные входы/выходы. Зависимости — `requirements-native.txt`.
Игра, сеть, реальные ключи и аккаунты не использовались.

## Найденная цепочка

Ранее найденный `0x1444ddc10` вызывает `0x14451d5c0` для элементов secret constants.

| Вызов внутри `0x14451d5c0` | Подтверждённое наблюдение |
|---|---|
| `0x14451d723` → `0x1483f9780` | Буфер ключа; в callee есть `crypto\bio\bss_mem.c` |
| `0x14451d773` → `0x148405720` → `0x148433880` | Литералы `ANY PRIVATE KEY`, `PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, путь `crypto\pem\pem_pkey.c` |
| `0x14451d8dd` → `0x141523200` → `0x14150cd70` | Base64 ciphertext; режим 0, стандартная таблица алфавита |
| `0x14451d8fa` → `0x148404190` | Пятый аргумент 3; wrapper вызывает RSA method slot `0x20` |
| `0x14451d946..0x14451d960` | Удаляются начальные нули RSA-результата, его исходная длина сохраняется |
| `0x14451d960/968` → `0x148404110` | Оба вызова возвращают descriptor `0x14a722610`: type 672, pkey type 668, digest size 32 |
| `0x14451d999` → `0x148405020` | OAEP: output capacity и num равны исходной длине RSA-результата; вход сдвинут на нулевой префикс; label=NULL/0, digest и MGF1 digest одинаковы |

Сопоставление с официальными исходниками **той же версии** OpenSSL указывает на
чтение private key, `RSA_private_decrypt` с `RSA_NO_PADDING`, затем
`RSA_padding_check_PKCS1_OAEP_mgf1` с SHA-256 для OAEP и MGF1, пустой label.
Это вывод из структуры, аргументов и литералов, а не найденные имена экспортов:
[RSA method layout](https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_1_1t/crypto/rsa/rsa_local.h),
[RSA wrappers](https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_1_1t/crypto/rsa/rsa_crpt.c),
[padding definitions](https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_1_1t/include/openssl/rsa.h),
[OAEP implementation](https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_1_1t/crypto/rsa/rsa_oaep.c),
[digest definitions](https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_1_1t/crypto/evp/m_sha1.c),
[NID definitions](https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_1_1t/include/openssl/obj_mac.h),
[private-key reader](https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_1_1t/crypto/pem/pem_pkey.c).
Побайтовое соответствие всей библиотеки upstream не заявляется.

## Исполнение и общий код

В Unicorn выполнен настоящий Base64 core с заранее выделенным выходом:
26 корректных входов от 0 до 1536 байт с padding и без него, восемь граничных
входов. Native допускает некоторые неканонические формы и может оставить
частичный результат при ошибке. Wrapper с аллокацией не исполнялся.

Отдельно исполнена подготовка OAEP и getter digest: 16 комбинаций длины
64/128/256/512 и нулевого префикса 0/1/2/вся длина. Вызов OAEP перехвачен,
аргументы сверены, результат искусственный. **RSA и OAEP не исполнялись**;
private key, backend и совместимость с сервером этими тестами не проверены.

Общий [sdk_constants.py](../../vampir-shared/vampir_core/sdk_constants.py) содержит
`decode_sdk_base64`: только stdlib, до 2048 символов и 1536 байт результата.
Принимаются канонические padded/unpadded строки; неправильные padding,
unused bits и алфавит отклоняются без частичного результата и содержимого
в ошибке. Политика строже native. Пустая строка даёт пустые bytes; пригодность
длины для конкретного RSA-ключа проверяется отдельно.

Пять тестов сверяют provenance, native результаты и повторное исполнение.
Далее: private-key формат → реальное RSA/OAEP на искусственном ключе → структура
secret constants → auth bindings. Метод lookup DECKEY через virtual slot `0x28`
остаётся неизвестным. `network_ready=false`, вход и бой не готовы.
