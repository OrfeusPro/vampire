# Общий reader: замена привязки и повторное использование слота

25 октября 2026. Продолжение [reader](UI-CONFIG-READER-11316.md) и
[native uniqueness](UI-CONFIG-UNIQUENESS-11316.md).
EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Offline replay, synthetic память; игра, реальные профили / настройки и
действующий UI snapshot не изменяются. Генерация остаётся закрытой до аудита.

## Источники и режим проверки

Задание `a161695d704bb8af36e950c7d8f2705ae0d6834756e8bb939eaec6208bc24832`
явно содержит шесть roots: 1445c2c30 / 1445c1f50 / 1445c4f60 / 141421b80 /
1445d8430 / 1445c29f0. Все уже ready; collect вернул reused / addresses=[].
Receipt во внешней библиотеке:
`knowledge/collections/57809c88073a7fc53cb7c85eea3a77379aeae4ffc5ff72a7bd53b1701a5d8fb0/manifest.json`.
Новые Ghidra exports не создавались. Пути / SHA готовых details сохранены
в двух предыдущих доказательствах и в зарегистрированных artifact dependencies.

В `replay-ui-config-reader.py --native-replacement` убран uniqueness=false
fixture. Reader, insertion, lookup, точный UTF16 compare leaf / ASCII table,
replacement и capture-copy / cleanup исполняются кодом клиента на одной памяти.
Точные leaf bytes / padding / slots таблиц проверяются по прежним доказательствам.
Старый new-entry режим сохранён как отдельная регрессионная проверка прежних
ограниченных сценариев; он не выдаётся за новый native replacement режим.

## Проверенная последовательность

Каждая последовательность содержит шесть полных вызовов reader:

1. Добавить ContentSubName: новый slot 0, capture первого destination.
2. Прочитать contentsubname: native compare находит slot 0; новый slot 1
   освобождается после переноса payload в slot 0.
3. Добавить Demo.Second: native insertion повторно использует slot 1.
4. Повторить Demo.Second: новый slot 2 освобождается после замены slot 1.
5. Добавить Demo.Third: повторно используется slot 2.
6. Прочитать CONTENTSUBNAME: заменяется slot 0, временный slot 3 освобождается.

Имена Demo.* и альтернативные sections — synthetic входы. Section передаётся
lookup, а проверенный контейнер сохраняет key / destination / callable objects.
Это наблюдение выбранной цепочки, не универсальное правило namespace конфигов.

Проверены все 64 сочетания found / missing шести lookup, три группы значений
(обычные / пустые строки, нулевой FString, кириллица, surrogate pair, slash,
длинная строка) и два режима destination: общий адрес повторного ключа либо
разные адреса при каждом чтении. Всего 384 последовательности / 2304 полных
возврата reader, 1152 replacements и 768 случаев reuse.

## Проверяемые инварианты

- В новом режиме нет host решения о совпадении ключей: native lookup и compare
  вызываются 1920 и 1152 раз соответственно. В каждой последовательности три
  replacement и два reuse; insertion возвращает индексы 0 / 0 / 1 / 1 / 2 / 0.
- Временный FString ключа очищается native переносом. После replacement
  free fixture помечает bytes старого ключа DD; действующие записи указывают
  на новые key buffers, сохранность которых проверяется после каждого вызова.
- Сохранённые invoke pointers и захваты каждого живого элемента соответствуют
  своему последнему destination. Смена destination не меняет значение прежнего.
  При общем destination missing lookup сохраняет предыдущий synthetic результат;
  при found изменяет его только assignment fixture.
- Проверяются все известные поля key / payload, hash links, allocated count,
  occupancy bitmap, free-list, capacity / storage pointers, inline bucket,
  moved-key source и guards. Новый слот освобождается с prev / next = -1.
- Native capture-copy выполняется дважды на вызов; cleanup — дважды для
  временных объектов и ещё дважды при замене старой привязки. Всего 6912
  native cleanup вызовов. Освобождение ключа не считается освобождением destination.
- В финале три действующие записи, четыре allocated slots и free slot 3;
  реальная bucket chain прочитана обратно как 2 → 1 → 0 → -1.

## Явные fixtures и ограничения

Остались восемь services: virtual lookup, конструирование / присваивание FString,
append-bit, hash, string free, memmove и cookie service. Их аргументы и порядок
проверяются отдельно. Освобождение старого ключа симулируется poisoning, реальный
allocator не вызывается. Bit-count обслуживается fixture и не объявлен полной
подтверждённой схемой TBitArray. Native hash пока не исполнен: один bucket
намеренно сохраняется для всех synthetic hash значений.

Контейнер заранее выделен на четыре slots; growth / rehash не нужны в этой
последовательности. Случаи нескольких свободных slots, ошибки / reentrancy,
общий container lifetime, реальные sources / precedence и последующий вызов
сохранённых операций не проверены. Регистрация после missing подтверждена
только в этих fixtures; это не active settings или событие обновления.
Совместимость cooked компонентов, загрузка ресурса и Brush остаются открытыми.

## Воспроизведение

Unicorn 2.1.4 / Capstone 5.0.6. Проверяются полный SHA EXE, unwind roots,
точные leaf bodies / padding / обе таблицы; исполнение вне выбранного кода и
явных fixtures отклоняется. Все десять tests tile refresh прошли, включая
прежние 144 new-entry вызова и новый общий native replacement режим.

Отчёт вне Git: `code-clues/ui-config-reader-replacement-d00a-02.json`, SHA256
`ebe040c00b9135bf75000060eef9a8cde37157cb73275b5451bc576a42df3c9a`.
01 сохранён отдельно. Новый режим включён в source-bound план обновления;
после смены SHA адреса / схемы / результаты не переносятся автоматически.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-ui-config-reader.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/a161695d704bb8af36e950c7d8f2705ae0d6834756e8bb939eaec6208bc24832/manifest.json' --native-replacement --output 'F:/PhoneExit Resources/Vampir/code-clues/ui-config-reader-replacement-d00a-next.json'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_ui_tile_refresh.py -v
```

Далее — native hash / потребители сохранённых invoke pointers и условия вызова.
Настройка пути UI-ресурсов не считается активной по одному успешному replay.
