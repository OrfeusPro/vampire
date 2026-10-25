# Цель Reload: config-helper и отдельный реестр callbacks

25 октября 2026. Продолжение [диагностического NNV caller](UI-CONFIG-CALLERS-11316.md).
EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Offline replay, synthetic память; GNn / Reload не запускались в игре,
реальные профили / конфиги и существующий UI snapshot не менялись.

## Источники

Явное задание `8df7413aaf11d65bc58bb17d0d98dd4f2c0cd6e67078856a9a429115076fd0d3`
содержит root 1445d1cd0, точную цель двух ветвей ~ / Reload. Collect завершился
с collected / пустой очередью. Ghidra:
`ghidra/request-exports/<полный SHA EXE>/run-02b2772620dd/details.json`, SHA256
`ba66bd0a20e24fa4cdfb41782098848a2f1b8aeeda1dbcd350f7f8d1cb7760d4`.
Псевдокод и инструкции согласованы; целый root 1445d1cd0…1445d1eb8.

## Подтверждённая цепочка

Сначала сохраняется qword глобального объекта 14b2e60f0. Helper 14157cf70
выдаёт временный FString; при count 0 используется указатель на пустой literal,
иначе data. Затем 141534f70 получает девять аргументов:

1. Адрес объекта 14b2e5678, ранее передававшийся как filename object в reader.
2. Точный UTF16 literal Game по 1489f3bf0.
3. Ноль.
4. Low byte 1.
5. Low byte 0.
6. Low byte 1.
7. Low byte 1.
8. Полученный data pointer либо пустой literal 1489e1b34.
9. Сохранённый qword из 14b2e60f0.

Смысл флагов и двух глобальных объектов не доказан. Ненулевые data временной
строки освобождаются. В теле wrapper нет проверки результата config-helper
перед переходом к обходу реестра; это не доказательство реального error contract
helper, исключения / аварии / процессные эффекты не моделировались.

Затем обходится реестр по 14b1867f0, bitmap по 14b186800, count по 14b186818,
external bitmap pointer по 14b186810. Шаг записей — 0x60. Он отличается от
реестра key / read-write привязок 14b186130 с шагом 0xb0; объединять их нельзя.
Связь между двумя реестрами и функции регистрации callbacks пока не найдены.

Для занятой записи берётся invoke +0x10, external capture +0x20 либо inline
capture +0x30. Через table slot +8 получается адрес захвата, затем invoke
вызывается с RCX=capture-address. В replay используется настоящий ранее
проверенный getter leaf 14140e2f0; тело invoke — fixture, его смысл неизвестен.
Последующие переходы bitmap выполняет 14142e6f0, пока отдельный fixture.

## Проверка

`replay-ui-config-reload.py` исполняет целое тело wrapper и capture getter.
48 случаев: шесть форм occupied bitmap, inline / external bitmap и captures,
наличие / отсутствие временной строки, false / true результат config service.
Формы включают пустой count, count 1 без занятого слота, slot 0, разреженные
слоты 1 / 3 и границы слов 0 / 31 / 32 / 64. External bitmap и external capture
выбираются вместе в двух режимах; все их независимые сочетания не проверены.

Проверены девять аргументов config-helper, low bytes трёх stack bool без
выдумывания значения остальных stack bytes, cleanup только ненулевого data,
порядок config-service → callbacks, собственные capture каждого occupied slot,
72 callback вызова, полный RIP / RSP возврат, неизменность реестра / bitmap /
entries / guard bytes. False / true service result дают один порядок обхода.

Начальный выбор occupied bit и пропуск нулевых bitmap words исполняются native
кодом. Последующее продвижение итератора — synthetic fixture с явным текущим
индексом / owner / следующим индексом; оно не доказывает весь native iterator.
Тела path helper, config-helper, free и callbacks также fixtures. Реальный
файл не читается, callbacks не считаются setters и не объявляются UI-событиями.

Итого: доказан локальный порядок и ABI wrapper, но не перечитывание конкретного
файла, source precedence, актуальность конфигурации, уведомление определённого
окна или изменение prefix / Brush. Название Reload не закрывает эти вопросы.

## Повтор проверки

Unicorn 2.1.4 / Capstone 5.0.6. Проверяются полный SHA EXE, unwind root,
глобальные references / literal / calls, stride, точные leaf bytes / padding
и getter slot. Выход за выбранные тела и явные fixtures отклоняется.
Все восемнадцать tests tile refresh / caller checks прошли; проверка включена
в source-bound план обновления без автоматического переноса на следующий SHA.

Отчёт вне Git: `code-clues/ui-config-reload-d00a-01.json`, SHA256
`df50ed29d9e040e4803550e0b0ef9171da5847ac9657180b5374b9b5e30bdc94`.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-ui-config-reload.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/8df7413aaf11d65bc58bb17d0d98dd4f2c0cd6e67078856a9a429115076fd0d3/manifest.json' --output 'F:/PhoneExit Resources/Vampir/code-clues/ui-config-reload-d00a-next.json'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_ui_tile_refresh.py -v
```

Далее — точные helpers 14157cf70 / 141534f70 и регистрация callbacks реестра
14b1867f0. Источники / precedence и связь с UI проверять отдельно от обхода.
