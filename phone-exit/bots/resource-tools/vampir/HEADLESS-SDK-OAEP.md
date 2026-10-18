# Vampir — исполнение OAEP и декодирование одного secret chunk

19 октября 2026. Продолжение [секретной ветки GMC2](HEADLESS-SDK-SECRET.md).
H04b-secret частично: один секретный элемент расшифровывается offline,
но конфигурация с сервера и вход в игру ещё не получены.

## Источник и воспроизведение

Собранный Windows клиент:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
VA относятся к image base `0x140000000`; версия выпуска игры и соответствие
Android не установлены. Настоящие исходники C++ игры здесь не используются.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-sdk-oaep.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_sdk_oaep.py -v
```

Для воспроизведения нужны `requirements-native.txt` и отдельный
`requirements-crypto-analysis.txt`. Последний закрепляет версии и SHA256 wheels
cryptography 48.0.0/cffi 2.0.0/pycparser 3.0 для Windows x64, CPython 3.14.
Это не пакет Android. Wheels находятся в игнорируемой `.tools`, в Git не входят.
Проверенный независимый backend сообщает OpenSSL 4.0.0; версия библиотеки
в коде клиента остаётся 1.1.1t. Результат подтверждает алгоритм на искусственных
данных, а не тождество двух библиотек.

Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-sdk-oaep.json`, SHA256
`f5bc01b7b1a68a7bacbc1dc9cb2a948bfd08321a0330be7c68d4a290f7b29fc5`.
Сохранены source/tool/fragment hashes, инструкции OAEP и caller, PEM-формат,
публичные параметры искусственных ключей, ciphertext, encoded messages и результаты.
Ключи генерируются заново при сборке отчёта, поэтому его хеш меняется.
Private key material не сохраняется и не выводится. Игра, сеть и аккаунты не нужны.

## Уточнение формата ключа и имён

На `0x14451d6f2` загружается ASCII-формат из `0x1494e2540`:

```text
-----BEGIN RSA PRIVATE KEY-----
%s
-----END RSA PRIVATE KEY-----
```

Это литерал с переводами строк; прежний printable-only scanner его пропускал.
В новом отчёте сохранены исходные bytes/offset/SHA и LEA caller.
Ключ передаётся как тело для этого PEM, а не как готовый PEM-документ.
У error branches найдены диагностические строки `BIO_new_mem_buf`
(`0x14451d730`), `PEM_read_bio_RSAPrivateKey` (`0x14451d786`),
`RSA_private_decrypt` (`0x14451d910`), `RSA_padding_check_PKCS1_OAEP_mgf1`
(`0x14451d9a6`). Они уточняют прежнее сопоставление с upstream;
именами экспортов эти строки не являются. Происхождение реального DECKEY
и семантика virtual slot `0x28` по-прежнему не восстановлены полностью.

## Что именно исполнено

В Unicorn выполняется настоящий OAEP checker `0x148405020`: дополнение входа
нулями, проверка первого байта/label hash/разделителя/ёмкости, перенос plaintext
и возврат ошибки. SHA-256/MGF1 заменены ограниченными hashlib shims; также
заменены allocator/free/cleanse/memcmp/error queue и MSVC stack helpers.
Аллокации ограничены двумя буферами до 512 байт и проверяются на освобождение.
Stack helpers сохраняют RAX, включая результат функции. Полный OpenSSL runtime
клиента, RSA arithmetic и его PEM reader в эмуляторе не исполняются.

Независимый backend генерирует искусственные RSA-ключи 2048/3072/4096 бит,
шифрует OAEP SHA-256/MGF1 SHA-256 с пустым label и проверяет decrypt.
Аналитический `pow(ciphertext,d,n)` даёт encoded message для native checker;
это только исследовательский расчёт, не криптографическая реализация продукта.
Для каждого примера тест проверяет обратную публичную RSA-связь с ciphertext.
Private key/PEM остаются только в памяти генератора.

24 корректных сценария: пустой plaintext, 1 байт, 32 байта, максимальная длина
`k-66`; encoded message полный и без начальных нулей. 69 ошибочных: первый
байт, label, нулевой/пустой вход, num меньше входа и недостаточная ёмкость.
При ошибке проверяется неизменность выходного буфера, при успехе — граница
записанных байт. Возврат 0 для пустого plaintext отличается от ошибки -1.

## Общий декодер и оставшаяся работа

[sdk_secret.py](../../vampir-shared/vampir_core/sdk_secret.py) содержит
`decrypt_sdk_secret_chunk(ciphertext, key_body)`. Вход ciphertext — стандартный
Base64, тело ключа — канонический ASCII Base64, оборачиваемый точным PEM-форматом.
Backend cryptography загружается только при вызове; остальное ядро от него
не зависит. Локальные границы: 8192 символа тела ключа, RSA 2048/3072/4096,
один ciphertext точного размера модуля. Whitespace/nested PEM, другие размеры,
неверные label/padding/ключ отклоняются. Ошибки не включают входные данные.
Возвращаются raw bytes: JSON, UTF-8 и объединение secret chunks здесь не имитируются.

Пять тестов проверяют source/provenance, все результаты отчёта, повторное native
исполнение, реальные backend roundtrips и отрицательные случаи API.
Готовность Android не подтверждена; до H06 криптозависимость нельзя считать
проверенной на двух платформах. Далее полный список secret constants, обработка
UTF-8/JSON, lookup DECKEY и привязка к authTokenUrl/clientId. `network_ready=false`.
