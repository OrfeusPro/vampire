# Реальное преобразование webViewType в 1.13.16

23 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [ветки дополнительных параметров](HEADLESS-NID-EXTENSIONS-11316.md).
Сохранённый EXE / synthetic memory; сеть, игра и авторизация не запускаются.

## Функция и значения

Явный prepare / collect для `0x1450ed350` получил export из 59 инструкций.
Diagnostic ASCII `0x14973c850` называет функцию
FNMServiceUtil::GetWebViewTypeByChannelType(enum ENMChannelType).
Полный SHA EXE, SHA export и байты каждой выполняемой инструкции проверяются.

| Входной byte | Возвращаемая строка | UTF-16 literal |
| --- | --- | --- |
| 30 | steam | 0x14952b730 |
| 31 | epic | 0x1497213d8 |
| 34 | xbox | 0x14952b788 |
| Все остальные | sdk | 0x14953a068 |

Native replay исполняет всю функцию с отключённым logging: byte по
`0x14b5632e0` равен 0. Logging helpers не подменены и не разрешены как targets;
попытка попасть в них остановит проверку. FString constructor / storage остаётся
fixture, копирующим настоящий UTF-16 literal из проверенного EXE.

1024 случая: все 256 значений byte × четыре poison fills. Проверяются результат,
возврат исходного destination pointer и canaries вокруг FString.

## Выполнение вместе с NID caller

`replay-nid-converter-11316.py` дополнительно исполняет прежний NID extensions
slice `0x1450e43d3..0x1450e48aa`, но converter теперь настоящий native-код.
448 случаев: четыре poison fills × modes 0 / 1 / 2 / 3 / 4 / 5 / 6 /
0xffffffff × channel byte 0 / 1 / 2 / 30 / 31 / 34 / 255 × optional object
пустой / непустой.

Для modes 4 / 5 channel byte влияет на `webViewType`; прочие modes передают
converter 0 и получают `sdk`. Подтверждены прежние authType и условное добавление
credential; fixture converter в этих случаях вообще не установлен.
Выбор runtime mode и фактическое значение channel global этим не установлены.

Это продолжение прежней проверки, а не подтверждение целой формы входа.
Map insertion, optional getter / virtual object / serializer / cleanup,
FString storage / free остаются fixtures. Настоящие credentials не используются.
Reference controller отсутствует, destructor branches не покрыты. Шесть коротких
cleanup tails caller закреплены отдельно по исходным байтам, как описано в
предыдущем evidence; export не переписан. Ранние gates, account additions,
query encoding, browser callbacks и успешная авторизация остаются открытыми.
Runtime profile по-прежнему не включён.

## Проверки и следующий update

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-nid-converter-11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid*11316.py
```

Восемь тестов по трём стадиям NID проходят: base pairs, extensions с fixture
converter и новый реальный converter / caller, включая отказы при повреждённых
материалах. Новый check `nid-converter-native-11316` зависит от двух exports,
replay tools и pinned native harness. Предыдущая проверка extensions сохраняется
отдельно; её результаты не подменяются новым доказательством.

В release-update-targets.json добавлены текущие адрес / scope / required_checks
и точная diagnostic signature для assisted поиска после смены SHA. Автоматически
можно повторять проверку зарегистрированной сборки. Для новой сборки нужно найти
и сверить функцию, три ветки / default literal и caller binding, затем перенести
check. Runtime автоматически не разрешается.

Библиотека `F:/PhoneExit Resources/Vampir/`:

- Export: `ghidra/request-exports/<SHA>/run-3ead5c3e47cf/details.json`,
  SHA `b196fbc036eecaacb9ed0dd256bf89ab69fc2d2bd596bf8877fc721745d84411`.
- Native report: `code-clues/nid-converter-11316/298c724525d9af006cea90ab976247a35a14d7c7fbac44d0fde62b420116b8da/manifest.json`.
- Caller export / source-bound cleanup bytes: предыдущий evidence по ссылке выше.

Следом проверить ранние URL / client ID gates и последующие account additions
в уже готовом NID export. Затем переносить auth source guards и подключение
SDK profile с отдельной проверкой живой сессии после доступности серверов.
