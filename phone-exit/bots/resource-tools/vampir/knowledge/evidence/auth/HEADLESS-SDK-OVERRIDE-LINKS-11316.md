# Связи игровых настроек SDK в 1.13.16

23 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [проверки начальных значений](HEADLESS-SDK-DEFAULTS-11316.md).
Это статическая сверка сохранённого кода, без авторизации и процесса игры.

## Как найдена ветка

Точная строка client ID `18e6xn1vuR1lGrvR` находится по адресу
`0x149859958` в UTF-16. У неё много инициализаторов: поиск с лимитом
32 unwind roots проверил 32, ещё три оставил с причиной исчерпания лимита.
По одной этой строке нельзя автоматически выбрать функцию настройки игры.

Для отдельной проверки выбран кандидат `0x14125b710`. Его инструкции
передают строку и destination `0x14b5e5f88` в `0x141426b30`.
По проверенным RIP LEA ссылкам на destination найдены сам инициализатор
и consumer `0x1456579d0`. Полный экспорт consumer показывает записи
в те же поля settings, которые ранее проверялись через конструктор.
Роль не переносилась по разнице адресов со старой сборкой.

Дальнейший поиск использовал только globals из инструкций consumer:
`0x14b5e5f78`, `0x14b5e5fc8`, `0x14b5e5fb8` и явный CALL
`0x14560aed0`. По ним получены три инициализатора и selector.
Из selector явно вызван getter `0x144529d60`; он выгружен отдельно.
Все семь функций получены через prepare / collect в отдельном проекте
этого SHA, без общего анализа EXE. Owning collect завершились успешно.

## Что видно в коде

| Инициализатор | Destination | Исходная строка |
| --- | --- | --- |
| `0x14125b710` | `0x14b5e5f88` | `18e6xn1vuR1lGrvR` |
| `0x14125b740` | `0x14b5e5f78` | `thered` |
| `0x14125b770` | `0x14b5e5fc8` | `nmp` |
| `0x14125b7d0` | `0x14b5e5fb8` | `epicgames` |

Consumer получает settings class через `0x1444b1fe0`, затем объект из
class+0x110. В непустой ветке он копирует default market в settings+0x28,
gameCode в +0x38 и client ID в +0x98. При наличии SDK singleton / handle
вызывает selector; результат 1 переключает market на второй global.
Операции копирования / выделения памяти здесь статически видны, но не исполнены.

Selector сравнивает результат getter со строками `nmp`, `epicgames`,
`gpgpc`. Getter передаёт UTF-16 `NMENV=` из `0x149543e98` в parser
`0x14158edf0` после вызова command-line getter `0x14152d5c0`.
Сам parser и фактическая командная строка игры не проверялись.

В конце consumer берёт environment string, передаёт ASCII `real`
из `0x149660f94` в comparator `0x14145f230`, обнуляет settings+0xc8
и записывает в settings+0x49 выражение `1 + (comparison == 0)`.
Это ещё не native-проверка сравнения, регистра строк или реального environment.
Вывод «активная zone точно 2» по этому этапу делать нельзя.

## Материалы и повторная проверка

Библиотека: `F:/PhoneExit Resources/Vampir/`.

| Полный экспорт | SHA256 details.json |
| --- | --- |
| `ghidra/request-exports/<SHA>/run-0716c15e22dc/details.json` | `4c40e76365d77eff13cf541ef2674797016ccf6e0a6d2b0664cf1d761a8dcfa6` |
| `ghidra/request-exports/<SHA>/run-9dc981740f54/details.json` | `f9ea52df7f73a60191e0d3515ad7585237925c1b7ad7839dff3f142ea7f9cd36` |
| `ghidra/request-exports/<SHA>/run-5e52997758ac/details.json` | `9aba1113b3baf9838e6721a9a73b5360a56b566e540d0627c5cfaeab9f194954` |

Проверенный поиск globals / прямого вызова:
`ghidra/request-exports/sdk-reference-candidates/2bf8243a48175a686173d65ef6eaab2a344c14d14a55cc26ed52ce013971f379/manifest.json`.
SHA manifest совпадает с именем каталога.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/find-release-sdk-references.py '<полный путь к run-0716c15e22dc/details.json>' --global-address 14b5e5fc8 --global-address 14b5e5fb8 --global-address 14b5e5f78 --direct-target 14560aed0
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sdk_references_11316.py
```

Пять offline тестов проверяют полный SHA источника и трёх exports, все
экспортированные инструкции, семь функций, четыре пары literal / destination,
строки real / NMENV, повторяемый поиск двух ссылок на default market.
Изменённая инструкция, неизвестный SHA и global вне supplied export отклоняются.
Эти тесты проверяют происхождение и статические связи, а не исполнение ветки.

Инструмент поиска теперь допускает два явно поддержанных SHA и выбирает
источник по supplied evidence. Добавлены лимит 64 roots до декодирования
и повторная сверка SHA источника / evidence перед сохранением отчёта.
Новый SHA сам по себе не разрешает перенос адресов или совместимости.

Далее исполнить текущие initializers, override, selector и getter в bounded
native replay с явными fixtures, включая real / NMENV и отсутствующие handles.
Затем сверить GMC2 URL / headers. Runtime profile и guards пока не изменены.
