# Актуальный источник CDN: ограниченные проверки, 19 октября 2026

Реальные NetworkSetting/CdnConfigUrl/AppVersion/ConfigPrefix пока не получены.
После [выбора lobby details](HEADLESS-CDN-SERVER-LIST.md) проверен один новый
кандидат ключа для закрытых ресурсов: SHA256 от уже подтверждённого compiled
CDN seed. На проверенных записях/каталоге он не подтвердился. Это отрицательное
наблюдение, не найденный PAK-ключ и не подтверждение отсутствия config.

## Источник и воспроизведение

Инструмент: [probe-cdn-key-in-pak.py](probe-cdn-key-in-pak.py).
Запуск: `python -X utf8 phone-exit/bots/resource-tools/vampir/probe-cdn-key-in-pak.py`.
Кандидат взят из SHA-bound [CDN fallback evidence](HEADLESS-CDN-FALLBACK.md),
EXE SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Seed bytes/file offset/SHA проверены в самом EXE до вычисления кандидата.
Это общая константа клиента, не ключ пользователя или аккаунта.

PAK: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Saved/PersistentDownloadDir/Patch/Install/pakchunk0-Windows.pak`.
Полный SHA256 `7c1efc7b799dd27d2580b4eed279755e60a92a6ce8ace1e9863038137122d179`.
Используется свежий [release index](CLIENT-RELEASE-INDEX.md) с SHA256
`8bf5db1a115f85b4eb7fbd2027620f459433b59450cdc62e06073ed0a2a9834e`.
Он принадлежит immutable release snapshot
`0f179fdafc09adab377e40314fd7409428b5961dc846ac300f8f1bb6b3111114`.
Перед чтением проверены полный archive/index/report hashes, размер и mtime;
после — неизменность размера/mtime. Старые кеши и offsets не используются.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/cdn-pak-key-probe.json`.
SHA256: `91677a2183ab982e8ab41ba29396a9fc5a7af861f12bb85e78aa4753ac79539b`.
Содержит источник, seed provenance, record hashes, header SHA1 и результаты;
plaintext не сохраняется, включая потенциальное совпадение.

## Результат и границы

- Восемь несжатых незашифрованных записей подтвердили соответствие header SHA1
  фактическому payload. Это control только для проверенного method-0 формата.
- Из 75 encrypted records 41 имеет method 0. У 18 полные cipher bytes входят
  в свежие границы записи: AES-256-ECB с CDN-кандидатом не дал совпадений SHA1.
- У 23 индекс не покрывает весь округлённый до блока ciphertext. Они явно
  пропущены, без чтения за границами и без признания неправильного ключа.
  34 compressed records этим способом не проверялись.
- Footer v11 показывает encrypted directory и нулевой GUID. Каталог 137680
  байт также испытан AES-256-ECB с тем же кандидатом. Его SHA1 не совпал ни
  с ciphertext, ни с пробной расшифровкой с обрезкой 0–15 байт padding.
  Каталог не разбирался, plaintext не использовался как конфигурация.

Это trial одного кандидата в явно выбранном режиме AES-ECB, не доказательство
того, как игра получает настоящий PAK-ключ. Native Oodle не вызывается на
пробных данных. Границы/gaps/остальные архивы и методы не охвачены.
Нет сетевых запросов, процесса игры или чтения файлов аккаунтов.

Три теста проверяют повтор actual pinned report, положительные artificial
plain/encrypted record controls, ошибочный ключ, hash mismatch/stale bounds,
отсутствующий cipher padding в индексе и directory hash/padding/bounds.

## Сохранённые clues по имени EncryptionKey

Инструмент: [build-pak-key-name-clues.py](build-pak-key-name-clues.py).
Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/pak-key-name-clues.json`.
SHA256: `0606ae964b37aec5a789809c63ee8f6c32fcaebbd47484145a3435b13750a90d`.
Три LEA к UTF-16 EncryptionKey подтверждены на границах инструкций:
`0x143945735`, `0x144fddc73`, `0x145045f04`.
Roots `0x143944d90`, `0x144fdd9c0`, `0x1450457c0` содержат context literals
AssetRegistry либо EOSSDK.Platform/artifact fields. Их код и literal provenance
сохранены; runtime семантика не исполнена. Связь этих имён с PAK-ключом
**не установлена**. Совпадение имени не используется как источник значения.

Далее искать подтверждённую регистрацию PAK-ключа или другой физический
источник Game config/late overrides. Доказанные URL builder/JSON/server-list
результаты сохраняются, но actual endpoints и `network_ready` остаются unknown/false.
