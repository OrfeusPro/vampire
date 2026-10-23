# Конструкторы и начальные значения SDK в 1.13.16

23 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [выбора базы GMC2](HEADLESS-GMC2-START-11316.md).
Исследование использует сохранённый EXE и синтетическую память, без игры / HTTP.

## Явный путь к функциям

Точный ASCII production URL дал unique RIP LEA owner `0x1444c4210` —
конструктор GMC2. UTF-16 `5.2.11` имеет несколько uses; короткий getter
`0x14452ac30` выбран для отдельной проверки и затем подтверждён исполнением.
Сами остальные uses строки не получили роль getter.

Новый Start вызывает settings class getter `0x1444b1fe0`. Его полный export
содержит ссылку на class callback `0x1444b2f20`. Проверены 20 байт leaf:
`488b014885c0740b488bd1488bc8e95d030000c3`. Он проверяет receiver, берёт объект
и делает JMP `0x1444b3290`; это явная связь к конструктору настроек.
Все четыре настоящих unwind roots получены через prepare / collect без
повторного импорта EXE и общего анализа. Leaf проверен по байтам отдельно.

## Native-проверка

`replay-sdk-defaults-11316.py` проверяет полный SHA EXE и двух exports,
затем байты всех исполняемых инструкций. Разрешены только инструкции трёх
явных функций и три fixture targets. Неизвестный native target останавливает
проверку. Capstone 5.0.6, Unicorn 2.1.4.

Девять случаев: четыре poison fills 0 / 0x55 / 0xaa / 0xff для settings prefix,
четыре для всего GMC2 constructor и один для getter версии SDK.
Settings исполняется от `0x1444b3290` до явной границы `0x1444b3339`;
GMC2 `0x1444c4210` и version `0x14452ac30` — до return.

| Начальное поле settings | Значение |
| --- | --- |
| +0x28 Market | пусто |
| +0x38 GameCode | thered |
| +0x48 BuildCode | 0 |
| +0x49 SDKZone | 1 |
| +0x50 SDKType | Global |
| +0x68 / +0x78 / +0x88 / +0x98 client IDs | пусто |

| Поле GMC2 manager | Текст |
| --- | --- |
| +0x150 | https://alpha-apis.netmarble.com/gc2 |
| +0x160 | https://dev-apis.netmarble.com/gc2 |
| +0x170 | https://apis.netmarble.com/gc2 |
| +0x180 | https://dr-apis.netmarble.com/gc2 |
| +0x190 service | netmarbles |
| +0x1c8 template group | netmarbles-v5 |

Getter возвращает строку `5.2.11` через fixture FString constructor.
У GMC2 проверены return receiver и poison canaries до / после объекта.

Fixtures: базовый конструктор settings возвращает receiver без записи;
ASCII/UTF-16 FString constructors читают точные literals из проверенного EXE
и помещают строки в ограниченную синтетическую память. Logging отключён.
Реальные FString / allocator, базовый UObject constructor и остаток settings
после prefix здесь не исполняются.

## Доказательства и проверки

Библиотека `F:/PhoneExit Resources/Vampir/`:

| Материал | Путь / SHA256 |
| --- | --- |
| GMC2 ctor, version, settings getter | `ghidra/request-exports/<SHA>/run-0cdca2f717ea/details.json` / `e5667cf351382f2ae5d7454010f6526cb24d0a11b49e86e87eb652c64babaf34` |
| Settings constructor | `ghidra/request-exports/<SHA>/run-d490839a48f4/details.json` / `ba186c8e32fccaecc4a5a4dae04b8df9d2c667327bec1309a6d5a9ce04fa0bb1` |
| Replay | `code-clues/sdk-defaults-11316/085c6a31a21012e5c69cad2ac827397bcedc4efe3e1493d99a2c482874e5f04d/manifest.json` |

Три offline теста подтверждают девять случаев и отклонение изменённых EXE /
export до исполнения. Семь locator tests также прошли после добавления двух
ориентиров: production URL и SDK version. Каждый anchor по-прежнему хранит
прежний SHA и адрес для provenance, не переносит его автоматически.

## Границы и дальше

Начальные SDKZone 1 и пустой Market не являются активными настройками игры.
Прежняя сборка меняла их game override, поэтому нельзя выбрать production URL
в новом runtime только по наличию строки или подставить zone 2 без проверки.
Класс settings getter получен статически; его lazy UObject registration не
исполнялось. Новые client ID, market, game override, URL builder и HTTP headers
остаются открытыми. Полный профиль входа пока не сформирован, guards сохранены.

Далее найти текущие initializers gameCode / market / clientId и их consumers,
проверить override для environment real и отсутствие NMENV, затем перенести
GMC2 URL / headers. Готовые exports повторно использовать из общего индекса.
