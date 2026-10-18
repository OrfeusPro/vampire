# Источник окружения SDK: CDN config

19 октября 2026. Продолжение [SDK settings](HEADLESS-SDK-SETTINGS.md).
Найдена цепочка до JSON-поля `NetmarbleS` → `Zone`; фактический ответ CDN,
его адрес и порядок полного запуска ещё не подтверждены. H04b частичен.

## Источник и воспроизведение

Собранный Windows EXE, не исходный C++ проект:
`C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256 `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
VA относятся к image base `0x140000000`; совпадение с Android не проверено.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-headless-cdn-config.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_cdn_config.py -v
```

Машинный отчёт `F:/PhoneExit Resources/Vampir/code-clues/headless-cdn-config.json`,
SHA256 `6fff1429a765f0be0d80b1d495f7c1db3846d5902887ff0178ea78dcad94c34a`.
Сохранены source/tool/settings-report hashes, 11 unwind roots, исходные инструкции,
literal references, vtable bytes и 7 native сценариев выбранного участка.
Используются закреплённые Capstone 5.0.6 / Unicorn 2.1.4. Сеть, процесс игры,
память launcher, файлы аккаунтов и пользовательской конфигурации не использованы.

## Цепочка объекта и загрузки

| Участок | VA | Что подтверждено |
|---|---|---|
| Конструктор объекта | 0x145631210 | Запись this в global 0x14b575630, обнуление +0x48 |
| Getter объекта | 0x14563d960 | Возвращает global 0x14b575630 |
| Vtable объекта | 0x1498bacd0 | Constructor пишет эту таблицу; slot+8 → 0x145647da0 |
| Инициализация значений | 0x145647da0 | +0x48 передаётся helper 0x141421dd0 с literal dev |
| Initialize | 0x14563f080 | Diagnostic FNnCdnConfig::Initialize, сборка параметров и HTTP callback |
| HTTP callback | 0x145642a30 | Diagnostic OnHttpPageLoaded, call ReadJson на 0x145643110 |
| Чтение JSON | 0x14565a5d0 | Diagnostic FNnCdnConfig::_ReadJson; отдельный участок Zone ниже |
| Двухуровневый lookup | 0x14563da10 | Первый lookup по section, virtual object access, затем child lookup |
| Настройка SDK игры | 0x14561a930 | Ранее проверенный getter → object+0x48 → compare real → settings+0x49 |
| Caller настройки SDK | 0x145618910 | Прямой call InitSetting на 0x14561898d |

Значение `dev` — начальное, до JSON. Тип внутреннего поля +0x48 и семантика
helper 0x141433970 целиком ещё не исполнены; передача строки в SDK доказана
выбранными callsites и replay предыдущего этапа, а не живым запуском клиента.

## JSON section/key и запись поля

ReadJson создаёт строки Zone (`0x14565a753`) и NetmarbleS (`0x14565a766`),
передаёт их как R9/R8 в lookup `0x14563da10` на `0x14565a788`.
RDX — исходный объект JSON, RCX — объект конфигурации. Lookup сначала ищет
section по ASCII-folded hash через `0x141420380/0x14158a730`, затем получает
вложенное значение через virtual slot0 и child lookup `0x1415edc20`.
Точная семантика child-key comparison и JSON типов пока не исполнена.

При найденном значении вызывается `0x1415e48f0`, полученный FString передаётся
в `0x141421d80` с destination object+0x48 (`0x14565a7a8/7ac`). При отсутствии
значения branch `0x14565a790` ведёт в diagnostic/error участок `0x14565f540`.
В нём есть Failed to find key и NetmarbleSZone; нельзя считать отсутствие ключа
успешной конфигурацией с автоматически выбранным dev.

Участок `0x14565a753..0x14565a7c2` проверен на None/empty/real/REAL/dev/real-space/réal.
Исполняются реальные подготовка аргументов, ветвление и destination callsite.
JSON lookup, JSON→FString, copy и free — ограниченные capture shims;
это не исполнение native JSON parser или всей ReadJson. Для None выполнение
останавливается на входе missing diagnostic, записи поля нет. Для строк поле
получает точный fixture без trim или нормализации на исследованном участке.

## Откуда берётся CDN URL

Root `0x144aa6f20` содержит цепочки загрузки настроек:

| Section | Key | Destination global | Call |
|---|---|---|---|
| NetworkSetting | CdnConfigUrl | 0x14b520cf0 | 0x144aa703a → 0x1445bc080 |
| NetworkSetting | CdnConfigUrlQA | 0x14b520d00 | 0x144aa7057 → 0x1445bc080 |
| NetworkSetting | AppVersion | 0x14b520d10 | 0x144aa7074 → 0x1445bc080 |
| NetworkSetting | ConfigPrefix | 0x14b520d20 | 0x144aa7105 → 0x1445bc080 |

Helper `0x1445bc080` сначала вызывает virtual slot+0x58 конфигурационного
объекта с section/key/output и ссылкой на отдельную глобальную строку файла.
При успехе переносит строку в destination, затем выполняет дополнительную
регистрацию/обработку через `0x1445bb3a0`. Значение file-global и этот последующий
этап ещё не разобраны: нельзя по одному slot назвать конкретный активный INI
или исключить последующие overrides.

Initializer `0x1411dca50` задаёт ConfigPrefix строкой dev. Initialize CDN
проверяет наличие literal real в этом prefix и выбирает одну из двух базовых
строк, затем собирает дополнительные части адреса. Полный алгоритм поиска,
порядок overrides и законченный URL здесь не исполнены. Фактические значения
NetworkSetting и файл-источник ещё не установлены; helper загрузки требует
дальнейшего анализа. Не выполнять запрос с адресом, составленным по догадке.

InitSetting caller обращается к SDK service и readiness до настройки, затем
к wrapper 0x14454f590. Это статическая последовательность выбранной функции;
порядок загрузки CDN, callback, InitSetting и GMC2 Start в полном startup
ещё не доказан. Успех offline replay не закрывает эту зависимость.

## Следующий шаг

Проследить источник NetworkSetting и актуальные CdnConfigUrl/ConfigPrefix,
полный builder и callback order. После подтверждения адреса — получить публичную
конфигурацию, сохранить источник/version/hash, проверить schema и Zone. Затем
вернуться к GMC2, DECKEY и полной авторизации. Наличие найденных ключей не
подтверждает текущую production-среду или доступность сервера. network_ready=false.
