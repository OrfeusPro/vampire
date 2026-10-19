# Описания модулей base и patch

19 октября 2026. Из обоих проверенных архивов извлечены два публичных
descriptor-файла. Это упакованные данные клиента, не доступный исходный проект.
Оба файла совпали между base и patch, включая полный SHA256 payload.

| Путь | SHA256 payload | Размер |
|---|---|---:|
| ProjectRED/ProjectRED.uproject | `edc42c8b42a450dee044903118bbf2750ca4e0c7a665d45f9fdc8c18a6051023` | 5561 |
| ProjectRED/Plugins/NkPatch/NkPatch.uplugin | `307b0f3ad59ab0bf4ff4bbb58631708745f1625b55c5275051cbb6f284f23b71` | 849 |

Project descriptor `/Modules/4`: NnNetwork, RuntimeNoCommandlet, LoadingPhase=Default.
`/Plugins/23`: Name=NkPatch, Enabled=true. Plugin descriptor `/Modules/0`:
NkPatchRuntime, Runtime, LoadingPhase=Default. Одинаковая фаза не определяет
порядок исполнения функций и не доказывает время mount относительно Game cache.
Не выбирать base/patch INI на основании порядка строк JSON.

Инструмент [recover-module-descriptors.py](recover-module-descriptors.py).
Запуск: `python -X utf8 phone-exit/bots/resource-tools/vampir/recover-module-descriptors.py`.
Источники — [два config snapshot и архивы](HEADLESS-PAK-CONFIG-RECOVERY.md).
Проверяются полные SHA256 архивов, EXE и dependencies до загрузки native DLL;
key callback исполняется, main/full directories сверяются по plaintext SHA1,
payloads проверяются по stored ciphertext SHA1/decoded size. JSON pointers,
source offsets и SHA payload сохранены. Только четыре фиксированных output
имени, прежние config snapshots не меняются, сетевых запросов нет.

Указатель `F:/PhoneExit Resources/Vampir/code-clues/module-descriptor-recovery.json`.
Snapshot `F:/PhoneExit Resources/Vampir/module-config-snapshots/580e140a409faddaf21f2622e7ccd7e8028297a66a570e3c9bd493270902929a/manifest.json`.
SHA256 manifest равен имени каталога, рядом четыре descriptor payload.

Четыре теста повторяют recovery и сравнение обоих слоёв, проверяют JSON shape,
ранний отказ при изменении reference и output allowlist/immutable snapshot.
`declared_loading_phases_only=true`, `runtime_module_order_verified=false`,
`config_precedence_verified=false`. [Native callback/startup evidence](HEADLESS-CONFIG-STARTUP.md).
