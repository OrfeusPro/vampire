# Выбор класса: тип из тега и ID найденной строки

23 октября 2026. EXE SHA256
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [источника поля класса](HEADLESS-CREATE-CLASS-SOURCE.md).

## Статическая цепочка

Type getter `0x145c8df30` регистрирует размер `0x3f8` и имя
`/Script/RdFramework.RdPlayerStateCharacterCreate`. Helper `0x14641af30`
проверяет guard, lookup игрока и цепочку типа. Ранее объект обозначался в
fixtures как UI; установленный native тип — PlayerState создания персонажа.

Указанные ниже функции найдены через прямые E8 callers этого type getter.
Новый `--callers-of` в `find-release-sdk-references.py` проверяет границы
инструкций целых unwind roots. Для одного явного адреса найдены 22 roots;
экспортированы три выбранные записи нужного поля. Автоматического экспорта
дерева нет. Лимиты поиска: четыре явных экспортированных target, 64 roots,
256 кандидатов E8. Indirect, tail и inline варианты не покрыты.

Selector `0x146431390` просматривает теги объекта `+0x1e0 / +0x1e8` и ищет
префикс `Class_` длиной 6. Остаток передаётся converter `0x1457ba970`.
При отсутствии подходящего тега возвращается 100. Сам converter и конкретные
теги ресурсов этим разбором ещё не проверены.

Функция выбора `0x14642b0c0` после проверок режима и объекта получает тип и пол
из двух helpers. Значения типа 100 и пола 2 отклоняются. Для подходящего
PlayerState вызваны singleton `0x145897180` и lookup `0x145896a10` с байтовым
типом. Если строка найдена, её uint32 `+8` записывается в PlayerState `+0x360`;
иначе записывается sentinel 0. Пол сохраняется в `+0x364`.
Функция `0x14642be10` сбрасывает выбранный ID в sentinel.

Это объясняет важное различие: в запрос уходит ID найденной строки, а не
порядок кнопки и не обязательно байтовый тип. Полная функция выбора с engine
и UI не исполнена; приведённая цепочка пока статическая.

## Native lookup

`replay-release-create-class-lookup.py` исполняет целые lookup и sparse iterator
`0x14142e7d0`. Lookup проходит только занятые записи stride `0x1c8`, сравнивает
байт row `+0x28` с выбранным типом и возвращает первую подходящую row.

45 случаев проверяют пустую таблицу, одну запись, пять записей, пропуски и
35 слотов с внешним bitvector через границу 31 / 32. Тестовые ID начинаются
с `0x80000000` и намеренно отличаются от типа. Проверены первый match,
отсутствующий тип и неизменность row storage. Содержимое singleton, bitvector,
rows / types / IDs — fixtures, не таблица установленной игры.

```powershell
# Из phone-exit/bots
python -X utf8 -m unittest test_vampir_create_class_lookup
```

Native report:
`F:/PhoneExit Resources/Vampir/code-clues/release-create-class-lookup/1ca8f44e6930546b393d4be52138ae32da873ebc87f306f36924f52b40f6400a/manifest.json`.
Caller report в comparison `c7552efd2125-98802d550890/run-fd4956a37b3c`:
`sdk-reference-candidates/c5bfec90d90d772bf126a180131482c51e4b7f074d528be8683e3822a8c307c5/manifest.json`.
SHA256 обоих совпадают с именами каталогов.
Ghidra details: `run-a57f969d0b18`, `run-531bd3325484`,
`run-8166e3cc193a`, `run-7c46bc658360` в том же comparison.

## Что ещё нужно

Исторический каталог связывает Carnage / Gunner с Class Id 3 и Type 3,
но относится к EXE `c7552efd…`. Совпадение этих двух чисел не доказывает
текущий wire ID. Нужно подтвердить identity singleton / схему строки,
converter и реальные теги, затем актуальную строку Class установленной сборки.
После этого — допустимые параметры внешности / JSON и результат ID 104.
Создание по синтетическим ID, default 100 или одной старой таблице не включено.
