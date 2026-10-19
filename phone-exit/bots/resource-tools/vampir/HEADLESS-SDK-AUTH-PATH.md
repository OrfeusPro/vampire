# Auth-контекст и дополнительный каталог SDK

19 октября 2026. Продолжение [Load filename](HEADLESS-SDK-LOAD-DEVICES.md).
Источник — тот же Windows EXE, SHA256
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
VA при image base 0x140000000, это код клиента, не исходный C++ проект.

Инструмент: `replay-sdk-storage-auth-path.py`.
Отчёт `F:/PhoneExit Resources/Vampir/code-clues/sdk-storage-auth-path-replay.json`,
SHA256 `614161a0b43583363975f20f982d7cf5e08f3a6a036882e537bb74826f9d7eaf`.
Сохранены source fragment bytes/file offsets/SHA, diagnostic literals,
compare leaf/table и SHA инструментов/переиспользованных отчётов.

## Native gate и Load path

Load вызывает `0x14452adc0` на `0x14452c78c`; возвращённый AL определяет,
дописывать ли строку global `0x14b4f1ee0` перед filename. Gate:

1. Вызывает auth-context helper `0x144520a60` с двумя FString outputs.
2. Если helper вернул false, возвращает false.
3. Иначе сравнивает первый output с global `0x14b4f1a48` без учёта ASCII-регистра.
   Initializer `0x1411b55c0` через native FString constructor связывает global
   со строкой **netmarble**.
4. При совпадении записывает 1 в `0x14b4f13fd`, возвращает true.
   При несовпадении возвращает false, но не обнуляет этот global.

Полный gate исполнялся с выключенными verbose logs. Native ASCII compare
и table переиспользованы из NID primitives; constructor/path/join — из прежнего
filename replay. Auth-context helper, base directory и suffix — явные fixtures.
Токен-контекст задаётся искусственно, настоящий command line не читался.

Восемь fixtures: netmarble/NETMARBLE/other/отсутствующий context × prior global 0/1.
Совпадение даёт путь
`<fixture-base>/NetmarbleSDK/nid-profile-fixture/ServiceSetting.bin`;
остальные случаи — `.../NetmarbleSDK/ServiceSetting.bin`.
Суффикс nid-profile-fixture полностью искусственный, не найденное имя аккаунта.

Global `0x14b4f13fd` — тот же byte, который проверял
[post-restore device dispatch](HEADLESS-SDK-LOAD-DEVICES.md).
В данном helper он остаётся равным 1 после ранее установленного значения,
даже при последующем несовпадении context. Общий lifecycle/reset ещё не найден;
нельзя по одному false return считать, что весь процесс вышел из этого режима.

## Статический источник auth context

Helper `0x144520a60` извлекает поля с ключами `NMAUTH_TYPE=` / `NMAUTH_TOKEN=`
через command-line getter `0x141527b10` и parser `0x1415893d0`. Если outputs
недостаточно заполнены (FString count<=1), пробует `AUTH_TYPE=` / `AUTH_TOKEN=`.
Return true только при непустых обоих полях в рассматриваемом коде.
Эта цепочка только декодирована; реальный parser/launch arguments не исполнялись.
Наличие command-line полей не означает, что headless должен хранить/передавать
секреты через командную строку. Никакие реальные tokens не читались.

## Кто заполняет suffix

Verified LEA reference к `0x14b4f1ee0` привёл к root `0x14454c7a0`,
diagnostic `Netmarble::FService::SetupServiceSettingPath(void)`.
Эта функция тоже использует auth-context helper и сравнение с netmarble;
дальше содержит разбор данных, migration-related ветвления и вызовы обработки
строк/буферов, затем перенос FString в suffix global на `0x14454cc7c`.
Сохранены полные decoded fragments, но тело **не исполнялось**.
Не объявлять суффикс email, UUID, hash, шифротекстом или аппаратным ID без
проверки преобразований и их входов. Source diagnostic NetmarbleIdPath
объясняет назначение переменной, но сам по себе не доказывает формат.

Initialize `0x14452a383`, Save `0x14453d9af` и post-save setters gate
`0x14453dc9f` читают тот же byte **0x14b4f13fd**, что и post-restore dispatch.
Эти три references проверены по decoded instructions и сохранены отдельно.
Load берёт результат текущего gate вызова, Save читает сохранённый global.
При prior global=1 и false gate return они могут разойтись в искусственном
контексте. Полный runtime lifecycle/reset пока не найден; такой переход
в живом клиенте не воспроизведён. Сам Save этим replay не исполнялся.

## Практическое состояние

Теперь известна причина, почему нельзя всегда брать default base/filename:
auth-context может менять каталог, а runtime-global имеет свой lifecycle.
Реальные Saved/registry/launch arguments/device keys не читались; полный
Load/Save, serializer и успешная запись/восстановление файлов не проверены.
Основной аккаунт в локальном реестре остаётся без реальных ключей.

Далее: проверить SetupServiceSettingPath transformations и lifecycle общего flag,
затем устойчивый identity acquisition/SaveGame decode и SDK auth response.

Проверка: `python -X utf8 -m unittest discover -s phone-exit/bots -p 'test_vampir_headless_sdk_auth_path.py' -v`.
Тест воспроизводит report, проверяет все восемь outcomes и source anchors.
