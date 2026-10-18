# CDN: AppVersion, Windows platform и общий offline URL

19 октября 2026. Продолжение [сборки URL](HEADLESS-CDN-URL.md).
Подтверждены подготовка версии и compiled Windows platform chain. Реальные
CDN bases/prefix/AppVersion пока не получены; это не успешный запрос к серверу.

## Источник и воспроизведение

Собранный Windows EXE, не исходный C++ проект:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Image base `0x140000000`; адреса ниже — VA. Android/iOS клиент этим исследованием
не проверен: названия платформ получены из Windows кода клиента.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-cdn-preparation.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_cdn_preparation.py -v
```

Отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-cdn-preparation.json`,
SHA256 `7df9b499766246bd408bf08ee47f47cf605f2960c694669630d649fa49ab4819`.
Сохранены source/tool/prior-report SHA, 5 unwind roots в 16 fragments,
1121 инструкция, 3 anchors bytes/SHA, memchr/memcmp import provenance,
15 version replays, один compiled platform replay и 7 return-value fixtures.
Capstone 5.0.6 / Unicorn 2.1.4 закреплены существующей analysis средой.
Игра/аккаунты/память процессов/сеть не использованы.

## Преобразование версии

Initialize на `0x14563f287` вызывает `0x1445daf80`, передавая std::string версии,
поисковую строку точки и строку замены underscore. Начальные значения символов
и передача R8/R9 сохранены в инструкциях caller. Проверенный результат:

```text
1.2.3 → 1_2_3
1..2  → 1__2
.1.   → _1_
```

Выполнены настоящий replacement loop `0x1445daf80`, std::string copy
`0x1445d8e60` и replace helper `0x1445de490`. CRT memchr/memcmp/memcpy/memmove,
allocator/free и security-cookie check — ограниченные shims. Cookie shim сохраняет
RAX. JSON parser, HTTP и преобразование входного UTF-16 не исполнялись.

В 15 сценариях проверены пустая строка, отсутствие точек, одиночные/повторные
точки, leading/trailing dot, пробелы, slash/query text, SSO boundary и длинные
строки. Замена не разбирает semver, не нормализует остальные символы и не меняет
исходный std::string. Для ASCII входов получено точное соответствие replace('.', '_').
Это не утверждение о реальной версии установленной игры.

## Откуда взялся Windows platform code

Getter `0x1445e75b0` читает global `0x14b4f39c8`, получает vtable и tail-jump
в slot+0x38. Участок инициализатора `0x1445eadd0` на
`0x1445eae1b..0x1445eae42` выделяет 8 байт, сохраняет объект в этот global
и записывает vtable `0x1495045d0`.

По адресу slot `0x149504608` лежит target `0x141484e40`:
`mov eax,2; ret`. Исполнена вся названная цепочка, включая настоящий getter
и target, затем CDN branch `0x14563f555..0x14563f580`. Итог — code2/label window.
Только allocator ограничен shim. Это compiled initialization, а не чтение памяти
запущенной игры; последующие изменения global в живом процессе не проверялись.

Дополнительно семь branch cases получили явные возвращаемые теги
0/1/2/3/255/0x80000000/0xffffffff через shim только value method. Getter и
ветвление оставались настоящими. Результат: 1→ios, 2→window, остальные→android.
Эти fixtures не доказывают реализацию или готовность бота на Android/iOS.

## Общий код

В `vampir_core.sdk_config` добавлены:

- `prepare_cdn_version_ascii(app_version)` — точка→underscore, явный printable
  ASCII, локальный лимит 4096 байт; не угадывает текущую версию.
- `select_cdn_platform_label(platform_code)` — явный signed int32, bool отклоняется;
  1→ios, 2→window, остальные→android согласно ветке Windows клиента.
- `prepare_cdn_config_url_ascii(normal, qa, prefix, app_version, platform_code)`
  с keyword-only аргументами — выбирает явную базу по prefix, преобразует версию,
  выбирает label и вызывает ранее подтверждённую сборку URL.

Совместный offline тест использует native preparation и native URL tail с
искусственными настройками: `https://cdn.invalid/window/real/1_2_3/config.json`.
Runtime совпал с этим результатом. Настройки обязательны; автоматического
обнаружения, URL validation, HTTP method/headers/request или fallback CDN нет.
Наличие готовой строки не делает запрос проверенным или совместимым с сервером.

## Продолжение

Цепочка подготовки строки закрыта только для явных ASCII inputs. Нужно получить
фактические значения из Game config и проверить late overrides, преобразование
не-ASCII, порядок CDN callback/SDK InitSetting/GMC2 Start. Отдельно восстановить
HTTP request semantics — метод/headers/проверку ответа — до сетевого использования.
После подтверждения адреса и запроса получить публичный CDN config/Zone, затем
GMC2/DECKEY/constants и полноценный вход. network_ready=false.
