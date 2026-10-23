# Выбор базы GMC2 в 1.13.16

23 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [launcher-контракта](HEADLESS-LAUNCHER-CONTRACT-11316.md).

## Источник и найденная функция

В [машинный план обновления](../../release-update-targets.json) добавлена точная
ASCII signature `void __cdecl Netmarble::Service::FGMC2ManagerImpl::Start(void)`.
Прежняя функция `0x144509080`, literal `0x149537b28` относятся только к SHA
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
По новой строке и проверенной RIP LEA найден unique candidate `0x144508210`.

Обновлённый locator report в библиотеке `F:/PhoneExit Resources/Vampir/`:
`code-clues/update-targets/56a51c7ab96855de2397ad270c81019c55be5313efb6fb1d467b35619f24c85b/manifest.json`.
Явные prepare / collect получили только новую функцию, используя готовый
source-specific Ghidra project. Экспорт:
`ghidra/request-exports/<новый SHA>/run-d444f3f0abe1/details.json`, SHA256
`dc9da35e609aac46ae80416e86977844303165c937aece5e4a0c8ffeb3fb57c1`.
57 инструкций / 236 байт; decompilation completed. Owning collect завершён.

## Проверка нового native-кода

Тест `test_new_gmc_start_all_zone_bytes_to_copy_boundary` в
`test_vampir_requested_functions.py` сверяет полные SHA EXE и export, байты
всех 57 инструкций, затем исполняет новый Start в закреплённом Unicorn.

512 случаев: все 256 значений zone и flag 0 / 1. Class settings pointer задан
fixture getter `0x1444b1fe0`, settings уже существуют; constructor ветвь не покрыта.
Logging явно отключён. Выполнение останавливается на реальном tail JMP
`0x1445082f7` → `0x141441d60`; destination/source аргументы копирования захватываются.
Сам FString copy не исполняется и содержимое строк не подставляется как результат.

| Zone byte settings +0x49 | Source manager | Destination |
| --- | --- | --- |
| 0 | +0x150 | +0x1e8 |
| 2 | +0x170 | +0x1e8 |
| 3 | +0x180 | +0x1e8 |
| 1 и 4–255 | +0x160 | +0x1e8 |

Каждый случай также проверяет копирование settings byte +0xc8 в global
`0x14b1860f4`. Ни один случай не вызывает HTTP, авторизацию или игру.
Весь набор requested collector теперь содержит семь проходящих тестов.

## Ограничения и следующий шаг

Это bounded native проверка только до copy boundary. URL, инициализация четырёх
FString, default zone, game override, SDK version, заголовки и GMC2 URL builder
не подтверждены. Роль текущего settings getter определяется здесь только как
граница fixture; его реализация не исследована. Статический C включает смысл
tail copy, которого нет в экспортированном теле Start; это не whole-copy replay.

Прежнее ориентировочное имя `FNnNetmarbleSDKService::_InitSetting()` не найдено
как точная строка в прежнем EXE. Оно не добавлено в автоматические anchors.
Для game overrides нужно использовать проверенные globals / initializers и
явные новые ссылки. Повторять поиск этой отсутствующей строки без новых данных
не нужно.

Далее — текущий GMC2 constructor, который заполняет +0x150…+0x180, settings
defaults и game override. Новый runtime profile по одному Start не создаётся;
guards прежнего профиля сохранены. Живой вход после обновления ещё не проверен.
