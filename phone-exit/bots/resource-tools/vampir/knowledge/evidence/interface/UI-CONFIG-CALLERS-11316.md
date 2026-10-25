# Вызывающий контекст consumers: диагностический путь NNV

25 октября 2026. Продолжение [registration / dispatch](UI-CONFIG-REGISTRATION-DISPATCH-11316.md).
EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Статический offline анализ; новые callers не исполнялись, команды игры и
диагностические команды не отправлялись. Профили / настройки не меняются.

## Поиск и источники

`knowledge-index.py callers` для 1445cbd00 / 1445d6ec0 с --release installed
вернул пустые results. Это ограничение готового индекса exports, не доказательство
отсутствия вызывающих функций. Задание
`0568a3bb2d4cf4d549a60f00a11628250c7655ccc83723ceef381cc503689546`
зафиксировало два известных consumer roots и причину узкого поиска.

Read-only поиск E8 patterns только в .text для двух точных targets дал четыре
кандидата. Каждый проверен полным decode unwind owner и точным call target:

| Callsite | Target | Unwind owner |
| --- | --- | --- |
| 1455086df | 1445cbd00 | 1455086b0 |
| 1455094f0 | 1445cbd00 | 145509470 |
| 145517933 | 1445cbd00 | 145517810 |
| 145517a35 | 1445d6ec0 | 145517810 |

Это все совпадения данного узкого direct-E8 поиска, не полный граф косвенных
вызовов / регистрации команд. Raw E8 bytes сами по себе не считались вызовами.

Явное задание `6ad9915eba63ac0d20a1ceaf352efc4d2fd2725b6d2847213e635d6b3cce47c0`
выгрузило три выбранных owners. Collect завершился с collected / пустой очередью.
Ghidra: `ghidra/request-exports/<полный SHA EXE>/run-e33a32096278/details.json`,
SHA256 `fdc94fb45fbc05154c60aa1839b6b78589ec4ff2b6ad49a2fc8a909736d8c31b`.
`inspect-ui-config-callers.py` сверяет полный source SHA, roots, семь calls,
восемь точных UTF16 literal references и выбранные data-flow / branch gates.

## Что подтверждено статически

1455086b0 читает значение ключа consumer и передаёт key / value в formatter
с точным шаблоном `\t%s = %s\n`, затем в строковый helper 141429e10 для
объекта из первого аргумента. Formatter / output здесь не исполнялись.
145509470 перед чтением выполняет дополнительный поиск helper 14142e020;
результат -1 обходит чтение / форматирование. Семантика этого поиска не доказана.

145517810 содержит точные литералы GNn, ~, Reload, сообщения о неизвестной
подстроке в NNVs и перечислении potential / all NNVs. На этом основании
вызывающий контекст — кандидат диагностического NNV пути. Его фактическая
регистрация как команды, доступность console, разрешения и инициатор не найдены;
обработчиком пользовательских настроек UI он не объявляется.

Выбранные цепочки инструкций:

- Входной строковый объект из RDX копируется, R8 сохраняется как второй
  строковый аргумент. Для GNn передаются length 3 и flag 1 в 141438a20;
  при ненулевом результате вызывается 141438180 с аргументом 3 и заменяется
  временный строковый объект. Точное правило prefix matching / удаления
  helper ещё не исполнено, регистр и формат команды не угадываются.
- Нулевой count ключа или count−1 ==0 переходит к сообщению
  `List up all NNVs ...` и iterator 1445cb6c0.
- Сравнение с ~ или Reload приводит к одному target 1445d1cd0.
  Этот target не исследован; слово Reload не доказывает перечитывание файла,
  сеть, применение настроек или изменение resource prefix.
- Остальной непустой ключ передаётся read consumer 1445cbd00. Результат
  с count <=1 строит сообщение `The specified substring[%s] is not exist in NNVs.`
  и `List up potential NNVs ...`, затем вызывает iterator с другим callback.
  Здесь count <=1 объединяет отсутствующий binding и существующую пустую строку;
  эта ветвь не является надёжной проверкой отсутствия ключа.
- Только при read count >1 проверяется второй входной string count. Если
  его полезная длина count−1 ненулевая, вызывается write consumer 1445d6ec0
  с key и новым value pointer. При пустом новом значении write обходится.

Следовательно, найденный caller не подтверждает произвольную запись пустого
значения или пустого binding. Прежние offline-прогоны прямого consumer остаются
верны в своих границах, но не доказывают доступность тех же действий через
данный диагностический путь. Косвенные callers и другие контексты не исключены.

## Применение в автосборщике

Граф знаний теперь различает регистрацию key/captures, прямые read/write
consumers и этот диагностический caller. Ни наличие setter, ни GNn / Reload
не становятся UI click binding или действием бота автоматически.
Источник активной конфигурации / precedence, реальные события / UI применение,
файловая persistence и условия caller остаются открытыми.

Отчёт вне Git: `code-clues/ui-config-callers-d00a-01.json`, SHA256
`9a4a161dffabdddb4d548912f0e1f01e2f83fee31b80e99b524aa3b08ea40cfb`.
Все семнадцать tests tile refresh / static caller checks прошли; новая
проверка не выдаёт статический анализ за native выполнение caller.
Source-bound план обновления сохраняет эти границы, без runtime promotion.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-ui-config-callers.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/6ad9915eba63ac0d20a1ceaf352efc4d2fd2725b6d2847213e635d6b3cce47c0/manifest.json' --output 'F:/PhoneExit Resources/Vampir/code-clues/ui-config-callers-d00a-next.json'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_ui_tile_refresh.py -v
```

Далее — отдельное задание на 1445d1cd0 и helpers prefix / инициатора caller,
сначала проверить их роль. Не запускать GNn / Reload в игре по этому выводу.
