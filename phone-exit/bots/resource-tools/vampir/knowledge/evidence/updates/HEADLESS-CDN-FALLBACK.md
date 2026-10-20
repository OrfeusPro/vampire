# CDN: запасная расшифровка тела, 19 октября 2026

После [получения тела/BOM](HEADLESS-CDN-BODY.md) найдена и проверена запасная
ветка `0x145653dd0`: первые 16 байт тела — IV, остальные — шифротекст;
ключ получается SHA-256 от встроенной строки клиента. Общий модуль возвращает
расшифрованные bytes. Реальный CDN config, его адрес и применение не проверены.

## Источник и воспроизведение

EXE: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Это собранный код клиента, не исходный C++ проект. Аккаунты и процесс игры
не использовались; все plaintext/IV/ciphertext в проверке искусственные.

Инструмент: [build-headless-cdn-fallback.py](../../../build-headless-cdn-fallback.py).
Запуск: `python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-cdn-fallback.py`.
Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/headless-cdn-fallback.json`.
SHA256: `bc9e14df56bd151c96cfa00e833f92312ab7dcaa99d213a4cd593231294f091e`.
В нём source/tool/prior SHA, инструкции/offsets/bytes, литерал seed, getter/
descriptor bytes, связь с именем шифра, backend versions и результаты 21 сценария.
Capstone 5.0.6/Unicorn 2.1.4; crypto dependencies закреплены в
[requirements-crypto-analysis.txt](../../../requirements-crypto-analysis.txt).

## Цепочка callback и параметры

Статически: call `0x145642c6d` → JSON parser `0x1415dd890`, затем проверка
успеха и ненулевого объекта. При успехе branch `0x145642c82` → ReadJson callsite
`0x145643110`. Иначе клиент получает исходный body pointer через `0x1445e6f70`,
длину через `0x1445e7440`, копирует bytes в vector и вызывает fallback на
`0x145642d52`. Это статические связи, не исполнение целого callback/JSON parser.

| Этап | Подтверждение |
|---|---|
| Минимальный вход | При размере меньше 16 native сразу возвращает пустую строку |
| Seed | Native собирает 28 байт `netmarble_neo_vam_1234567890` из EXE |
| Key derivation | Call `0x145653ec3` → SHA helper `0x1483f9cd0`, output 32 байта |
| IV | Native копирует первые 16 байт в отдельный буфер |
| Ciphertext | Native копирует всё после IV, не удаляя BOM и NUL |
| Cipher getter | `0x14840a8b0` выбирает один из двух descriptors по CPU flags |
| Descriptors | `0x14a723e80` / `0x14a723e20`: nid 427, block 16, key 32, IV 16 |
| Имя алгоритма | Compiled ASN.1 record nid 427 указывает на `AES-256-CBC` |
| Init/update/final/free | Calls `0x148406a20` / `0x148406a50` / `0x148406850` / `0x1484061f0` |

Seed — общая константа собранного клиента, не пароль/ключ аккаунта или сопряжения.
Её bytes/file offset/SHA и record с именем шифра сохранены в отчёте. SHA helper
статически содержит стандартные SHA-256 initial state и размер digest 32.

## Что именно исполнялось

Целиком исполняется fallback orchestration: подготовка seed/key/IV/vector,
выбор descriptor, вызовы crypto, ветви ошибки, копирование результата и cleanup.
Настоящий getter исполнен для двух явных CPU-flag fixtures, оба descriptors
связаны с тем же nid. **SHA256/EVP primitives заменены явно отмеченными
backend shims**: hashlib и cryptography AES-CBC с PKCS7. Native AES/SHA core
не исполнялся. Их статические roots сохранены для дальнейшей проверки.
Не выдавать эти сценарии за доказательство исполнения native криптографии.

17 обычных сценариев включают короткие/неполные входы, пустой plaintext, JSON,
кириллицу, NUL, SSO/heap строки и ошибочный padding. Ещё три принудительно
возвращают ошибку init/update/final; один проверяет второй descriptor.
На всех проверенных return paths crypto context освобождён. Нативная функция
при crypto failure возвращает пустую строку, как и для пустого plaintext.
Проверка PKCS7 в этом прогоне выполняется backend shim, а не native EVP final.

## Общий переносимый модуль

[cdn_fallback.py](../../../../../vampir-shared/vampir_core/cdn_fallback.py):
`decrypt_cdn_fallback(payload)` → raw plaintext bytes, без Unicode/JSON parsing,
сохранения на диск, сети и применения settings. Optional cryptography загружается
только при вызове; при отсутствии выдаётся понятная RuntimeError. На Windows
проверен cryptography 48.0.0; Android crypto backend ещё не проверен.

**Локальная политика:** IV16 + хотя бы один AES block, длина ciphertext кратна
16, общий envelope максимум 2 МиБ, строгий PKCS7. Ошибка вызывает ValueError
без входных данных; корректный пустой plaintext возвращает `b''`. Это явно
отличается от native пустой строки при ошибке. Дополнительная аутентичность
или пригодность конфигурации расшифровкой не устанавливается.

Семь тестов проверяют source/literal/descriptor/name bytes, все 21 native
orchestration replay, key/IV/ciphertext capture, forced errors/cleanup,
portable plaintext vectors, неверный padding, максимальный envelope, отсутствие
backend и цепочку Content-Length → whole raw body → decrypt → Unicode text.

Продолжение: [JSON flow и SDK environment](HEADLESS-CDN-JSON-FLOW.md).
Следующий этап: реальное исполнение crypto primitives либо независимые native
vectors, JSON parse/fallback/ReadJson acceptance, актуальные CDN settings/TLS,
Content-Encoding/chunked/EOF. `network_ready=false`.
