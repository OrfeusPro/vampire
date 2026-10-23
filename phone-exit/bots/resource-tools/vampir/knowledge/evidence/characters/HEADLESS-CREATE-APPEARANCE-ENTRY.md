# Внешность: поиск definition и ключ числового JSON-поля

23 октября 2026. EXE SHA256
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [входов генератора](HEADLESS-CREATE-APPEARANCE-JSON-INPUTS.md).

## Источник definitions

Helper `0x14566c5e0` строит путь по UTF-16 literal `0x149913f50`:
`Customize/DT_CustomizeBoneGroup%s`. Он получает строку для переданного byte
через `0x1416dd790`, удаляет начальный символ и форматирует путь.
Преобразование byte в суффикс пока разобрано статически; нельзя считать, что
любой byte автоматически означает допустимый пол / набор настроек.

Сохранённый исторический индекс
`F:/PhoneExit Resources/Vampir/pak-extracted/pakchunk100-Windows/entries.json`
содержит пути `/Game/RED/Blueprint/DataTable/Customize/DT_CustomizeBoneGroupF`
и `.../DT_CustomizeBoneGroupM`, записи 1018 / 1020. Это конкретные кандидаты
ресурсов для следующего извлечения. Их актуальность и строки в этой работе
ещё не подтверждены; старые offsets применять к текущему PAK нельзя.

Lookup `0x145466740` получает объект через `0x14566d1e0`, вызывает virtual
`+0x2e8` и обходит sparse collection pointer entries со stride `0x18`.
Predicate `0x14546c610` сравнивает имя настройки с definition `+8` через
строковый helper. Если definition не найдена, entry helper не пишет JSON-поле.
Эти lookup / predicate здесь разобраны статически, не исполнены целиком.

## Целый entry helper

`replay-release-appearance-json-entry.py` исполняет целый `0x1456746c0`.
Входная FString настройки копируется в predicate closure; byte режима
передаётся path helper. При найденной definition её uint32 `+0x10` передаётся
преобразованию текстового ключа. Полученная строка копируется в JSON setter
`0x1415f2740`; исходное имя настройки не подставляется непосредственно.
Float преобразуется в double native-инструкцией перед setter.

24 сценария: definition есть / нет, mode 0 / 1 / 255, значения 0 / signed zero /
0.125 / -2.5. Проверены отсутствие записи при missing definition, числовой ID
из отдельного поля найденной записи, использование отличающегося от input имени
ключа и точное преобразование float → double, включая signed zero.

Границы: mode helper, поиск definition, текстовый converter, JSON setter,
FString storage / copy / free и destructor объекта текста — fixtures / captures.
Число `0x12345678` и `converted_fixture_key` синтетические и не являются
реальными параметрами внешности. JSON output / engine map не воспроизведены.
Неизвестный режим не объявляется допустимым из-за прохождения fixture.

```powershell
# Из phone-exit/bots
python -X utf8 -m unittest test_vampir_appearance_json_entry
```

Native report:
`F:/PhoneExit Resources/Vampir/code-clues/release-appearance-json-entry/0cf79a46ee1962cc132ccf2149c20d8b16f967b93d7a11d98b11683a3400556c/manifest.json`.
SHA256 совпадает с именем каталога. Ghidra helper export — comparison
`c7552efd2125-98802d550890/run-fd4956a37b3c/details/run-e672aa1efaef/details.json`,
SHA256 `6a0fd26eb7e8f32925616325d2d5a55ad75c4eb4edbe22a099cf14eb29f8a418`.
Entry helper — прежний `details/run-770966be34b2/details.json`.
Проверка `release-appearance-json-entry` зарегистрирована с зависимостями.

Следом проверить текущие ресурсы BoneGroup F / M и их definitions, затем
реальный lookup / key converter, JSON output, whole producer и handler ID 104.
Сеть, игра и создание персонажей этой проверкой не выполняются.
