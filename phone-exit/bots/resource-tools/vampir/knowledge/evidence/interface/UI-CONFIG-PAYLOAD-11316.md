# Перенос двух callable-объектов настройки

25 октября 2026. Продолжение [строковых операций](UI-CONFIG-CALLABLES-11316.md).
EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Игра не запускается; профили / конфигурации и действующий прототип не меняются.

## Источники

Первое задание `aa492c71a43b7959c4abcb135a76c1e41a86a2c41a9f3bd458e27a05f6565268`
выгрузило точный callee 1445c4f60 из insertion helper. Ghidra:
`ghidra/request-exports/<полный SHA EXE>/run-218ed676dfab/details.json`, SHA256
`b2d468647ed1c90a3eb8ce6967ec78eed53f99fa0b4156dd031b98154c969c43`.
Псевдокод и инструкции согласованы: два условных virtual calls копируют
хранимые объекты, это не вызовы сохранённых строковых операций.

В reader 1445c2c30 ранее найден адрес общей таблицы 1489e4448.
Первые четыре slots: 141421b50 / 14140e2f0 / 141421b70 / 141421b80.
SHA256 этих 32 байтов:
`06fdf98a015821bf750f3f38fe68f4ffebd984872ee9720e0d00b4313b2ab0ea`.
В source-bound задании
`4a612281b4c37e4d856f9c3ce456c6b762f74b1c15b84ad7477f687895cd327a`
явно перечислены первые три адреса. У них нет unwind records; collector
не запускался. Exact bytes, terminal RET / tail jump и последующие INT3
проверяются replay отдельно. Роли не назначаются по соседству адресов.

Задание `443d4ffcc771f92692b64697d35029ab8c1beadc54666ab5026a4e5bf9b56a4c`
повторно использовало готовый export 1445c4f60 и добавило только unwind root
141421b80 — цель tail cleanup через slot +0x18. Ghidra:
`ghidra/request-exports/<полный SHA EXE>/run-21a346cf8c62/details.json`, SHA256
`64bfd80ae3d7bb109d26e5a61b00b6cf53ace539670542618db43b938ae9daed`.
Оба collector завершились с collected / пустой очередью.

## Native перенос

1445c4f60 копирует первый qword payload, указатели операций +0x10 / +0x50,
обнуляет destination storage +0x20 / +0x60. Для ненулевой операции выбирает
source external storage или inline object +0x30 / +0x70 и вызывает slot 0.
Сам invoke pointer в этой функции не вызывается.

Leaf 141421b50 записывает общую таблицу во встроенную область destination
и копирует один захваченный qword. Он не разыменовывает захваченный указатель,
не выделяет память и не изменяет source. Leaf 14140e2f0 возвращает RCX +8 —
адрес захвата, а не значение указателя. Имена типа source C++ не восстановлены.

`replay-ui-config-payload.py` исполнил полный helper и настоящий virtual copy
leaf в 48 сценариях: все сочетания двух active / inactive операций и двух
inline / external source storage, по три пары захватов, включая нули и разные
64-битные значения. Проверены весь destination, guard bytes, неизменность
source / external storage, число native copy вызовов и полный возврат.
На этих путях нет fixtures. Неактивная операция не очищает все inline bytes:
они остаются контрольными; это не готовый default для произвольного объекта.

## Native очистка

141421b70 обнуляет EDX и делает tail jump через slot +0x18 в 141421b80.
Последний устанавливает таблицу, проверяет младший bit DL и при его наличии
вызывает 141431f80 с размером 16; возвращает исходный объект. Deallocation —
единственный fixture этого replay, фактическая память не освобождается.

16 сценариев проверили оба входа с flags 0 / 1 / 2 / 3 / 254 / 255 / 256 / 257.
Tail cleanup всегда обходил deallocation; прямой destructor вызывал его только
при младшем бите. Для прямого входа неверная исходная таблица заменялась общей;
захват и guard bytes сохранялись. Ещё три сценария проверили address getter.
Эта локальная очистка не доказывает время жизни всего контейнера и destination.

## Повтор и оставшаяся работа

Unicorn 2.1.4 / Capstone 5.0.6. Проверяются полный SHA источника, unwind roots,
три leaf bodies / padding и четыре точных table slots. Исполнение вне выбранных
тел и deallocation fixture отклоняется. Внешние storage — synthetic mapped
объекты, захваченные указатели непрозрачны; происхождение allocation неизвестно.

Отчёт `code-clues/ui-config-payload-d00a-02.json` вне Git, SHA256
`22d6d43712a60f70b640ba88b69c406ae4494b740592fc69e751072512c3fa26`.
01 сохранён как пробный отчёт. Все семь tests tile refresh прошли, включая
48 copy / 16 cleanup / 3 address случая. Проверка включена в план обновления,
без автоматического переноса старых адресов на новый SHA.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-ui-config-payload.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/443d4ffcc771f92692b64697d35029ab8c1beadc54666ab5026a4e5bf9b56a4c/manifest.json' --leaf-request 'F:/PhoneExit Resources/Vampir/knowledge/requests/4a612281b4c37e4d856f9c3ce456c6b762f74b1c15b84ad7477f687895cd327a/manifest.json' --output 'F:/PhoneExit Resources/Vampir/code-clues/ui-config-payload-d00a-next.json'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_ui_tile_refresh.py -v
```

Далее — целый reader 1445c2c30 вместе с insertion 1445c1f50 и проверенным
payload copy. Отдельно ограничить storage / hash / uniqueness helpers,
проверить сохранённые захваты и cleanup на одной памяти. Реальное последующее
исполнение строковых операций, config precedence, active resource / Brush
и совместимость cooked компонентов ещё не доказаны. Генерация остаётся закрытой.
