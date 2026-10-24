# NkTileView: текущий getter класса и границы следующего разбора

25 октября 2026. Только статический offline разбор установленного EXE, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Нет исполнения native-кода, подключения к процессу или игровых команд.

Вопрос `ui-nktileview-property-schema`, запрос
`84e04121b72e4c6b6e89cf2d86892c670aaaaf162c31460a0bf48b0bcb980720`.
Подготовительный поиск точного UTF16 литерала NkTileView нашёл RIP-кандидат
144a66f66, принадлежащий unwind root 144a66f20. Индекс не содержал его экспорта;
prepare / collect запросили только этот root. Исследование продолжено по
завершённому экспорту Ghidra, а не по прежним адресам UI.

## Подтверждённая последовательность

Целая unwind функция 144a66f20..144a66fce декодирована с полным покрытием байтов:

1. В 144a66f27 читает глобальный указатель 14b591718. Ненулевой результат
   идёт через 144a66fc9 к возврату.
2. В нулевой ветви 144a66f54 подаёт адрес того же глобального указателя в R8.
3. 144a66f66 подаёт в RDX адрес 1496538c2 с точной UTF16 строкой NkTileView.
4. 144a66f75 подаёт в RCX адрес 14963dc20 со строкой /Script/NkUMG.
5. 144a66fbd вызывает 1416ab8d0. Среди передаваемых значений есть 0x470,
   0x10 и 0x10000000. Назначение аргументов этим исследованием не установлено.
6. После helper 144a66fc2 повторно читает 14b591718 и возвращает результат.

Это getter кешируемого указателя с точными именем класса / пакета; helper
и регистрационные side effects не исполнялись. 0x470 не объявляется доказанным
размером UObject и не задаёт схему сериализованных полей.

Передаваемые указатели 144a88f70, 144a6a620 и 144a2ec60 — кандидаты для
отдельного явного задания. Их роли constructor / registration callback /
superclass accessor пока не установлены. Getter не раскрывает порядок
UProperties, EntryWidgetClass, default, NkTileView factory или runtime updater.

## Воспроизведение и источники

Ghidra export:
`F:/PhoneExit Resources/Vampir/ghidra/request-exports/d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960/run-8024950972b3/`.
Проверены details.json и SdkLiteralOwner-144a66f20.c; псевдокод согласован
с инструкциями / RIP-целями, но не используется как доказательство типов.

`inspect-nktileview-registration.py` проверяет SHA EXE, явный root задания,
unwind, полноту декодирования, выбранные инструкции и точные литералы.
При другом SHA отказывает до применения адресов. Сохраняет весь fragment
с SHA и ограничениями. Отчёт вне Git:
`code-clues/nktileview-registration-d00a-01.json`.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-nktileview-registration.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/84e04121b72e4c6b6e89cf2d86892c670aaaaf162c31460a0bf48b0bcb980720/manifest.json' --output 'F:/PhoneExit Resources/Vampir/code-clues/nktileview-registration-d00a-next.json'
```

Файл результата должен быть новым. Повторный запуск на неизменённом источнике
должен воспроизводить те же fragment SHA; это статическая проверка, не replay.
Далее prepare / collect для трёх точных кандидатов и только затем их анализ.
Совместимость текущей схемы с прежними cooked пакетами проверяется отдельно;
[строка эффектов](../../../../../vampir/UI-STATUS-EFFECTS.md) ещё не подключена.
