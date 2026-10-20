# NetworkSetting: callback вызывается при регистрации

Продолжение: [base/patch module descriptors](HEADLESS-MODULE-DESCRIPTORS.md)
объявляют NnNetwork и NkPatchRuntime в одной фазе Default, порядок неизвестен.
По base INI профилю отдельно [получен публичный CDN config](HEADLESS-PUBLIC-CDN.md).
Это не доказательство active Game cache или порядка mount.

19 октября 2026. Порядок загрузки base/patch INI ещё не установлен.
Уточнено промежуточное звено: загрузчик NetworkSetting вызывается сразу
из registration helper, до вставки callback в реестр. Предположение о том,
что helper только откладывает загрузку на потом, этим исключено для проверенной
ветви. Содержимое INI и startup целиком не исполнялись.

## Источник и воспроизведение

[build-headless-config-startup.py](../../../build-headless-config-startup.py).
Запуск: `python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-config-startup.py`.
Данные/код клиента — установленный `ProjectRED-Win64-Shipping.exe`, SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Тот же источник, Capstone 5.0.6/Unicorn 2.1.4 и локальная цепочка инструментов,
что в [восстановлении INI](HEADLESS-PAK-CONFIG-RECOVERY.md).
Процесс игры, файлы аккаунтов и сеть не используются.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/headless-config-startup.json`.
SHA256 `4fcd7e6e2c61993b5b3999bde06459b4e59ae4f7c08d6f5f6e3e60b3d420413e`.
Содержит исходные инструкции, file offsets/bytes/SHA фрагментов, callback name,
vtable pointers, thunk/getter bytes и восемь воспроизводимых native slices.

## Подтверждённые связи

| Звено | Источник |
|---|---|
| Factory владельца | `144aa5810`, LEA `144aa5828` → vtable `14961a318` |
| Указатель функции владельца | vtable+8 (`14961a320`) → `144aa4810` |
| Владелец создаёт NetworkVar | call `144aa4886` → `144aa6e70` |
| Имя регистрации | LEA `144aa6e99` → literal `FNnNetworkVar` |
| Callback descriptor | `144aa6ea0` загружает thunk `144aa7500`, сохраняется в stack descriptor+0 |
| Registration helper | call `144aa6ecc` → `1445cd6c0` |
| Контекст | descriptor+10 выбирает внешний объект, иначе inline descriptor+20; virtual slot+8 возвращает closure payload |
| Native getter | `141408910`: `lea rax,[rcx+8]; ret` |
| Немедленный вызов | `1445cd714`: `call rbx` с callback из descriptor+0 |
| Thunk | `144aa7500`: tail jump → `144aa6f20` |
| Реестр | после callback call `1445cd734` → `1445bb590`; передаётся пара указателей name/descriptor |

Существующая связь `144aa6f20` → `1445bc080` → GConfig lookup логической
конфигурации Game описана в [CDN config](HEADLESS-CDN-CONFIG.md).
Factory registration `144aa5620` также включена как статический контекст:
LEA `144aa5684` указывает на factory. Это не доказательство порядка загрузки
модулей относительно PAK mounting или заполнения GConfig.

Отдельная статическая цепочка patch initialization:
`14563e2f0` call `14563e3ac` → `144a97cc0`, далее call `144a97f30` →
`144a97f60`. Эти функции включены в отчёт. Временная связь между ней и
загрузкой NetworkSetting пока не установлена.

## Что именно исполнено

Native slice `1445cd6f9..1445cd739`, context getter и callback thunk.
Восемь fixtures: inline/external context и четыре 64-bit marker значения.
Во всех случаях callback получает правильный closure payload и вызывается
раньше registry insertion. Marker — искусственное значение, не объект игры.

Тело загрузчика и вставка в реестр заменены capture shims. TLS/static-init
ветвь helper, prologue/epilogue, полноценный FString/name, владелец и factory
в этих fixtures не исполняются. Descriptor задаётся явно по полям constructor.
Не проверены полный registry lifecycle, reload и конкурентные вызовы.

Четыре теста сверяют EXE/инструкции/указатели/имя, повторяют восемь native
fixtures, воспроизводят отчёт и проверяют отказ до анализа при подмене EXE.
Это не проверка входа в игру или совместимости с сервером.

## Следующий открытый вопрос

Нужно связать вызов функции владельца через vtable с порядком module loading,
PAK mounting и первым заполнением GConfig Game cache; отдельно проверить reload
и поздние overrides. До этого оба извлечённых INI сохраняют самостоятельное
происхождение, ни один не объявляется active. `config_precedence_verified=false`,
`active_runtime_settings_verified=false`, `network_ready=false`.
