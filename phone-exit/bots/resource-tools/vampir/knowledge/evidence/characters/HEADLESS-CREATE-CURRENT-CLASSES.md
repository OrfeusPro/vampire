# Текущая таблица классов и Carnage

23 октября 2026. EXE SHA256
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [цепочки выбора класса](HEADLESS-CREATE-CLASS-LOOKUP.md).

## Identity и поля

Getter `0x145897180` возвращает singleton `0x14b1bdfd0`. Его начальные
указатели в текущем EXE: `0x1499777f0` и interface `0x149977828`.
В interface slot `+0x48` находится getter `0x145897850`, который строит строку
из ASCII literal `ClassInfo` по `0x1499777e0`.
Slot `+0x50` указывает на column loader `0x1458b76d0`.

Loader использует тот же stride `0x1c8`, что и lookup. Он сравнивает имя
колонки с ASCII `Type` по `0x148a36908`, вызывает converter и сохраняет byte
в row `+0x28`. Колонка `DefaultGender` записывается в row `+0x10`.
Converter `0x1457ba970` строит map с ключом ASCII `Gunner` по `0x14994fe58`
и значением 3; проверены LEA по `0x1457baad8` и запись байта по `0x1457baaf7`.
Это статическая связь ClassInfo / полей / converter. Полные loader и engine
map converter не исполнялись.

Таким образом, путь выбранного Gunner не зависит от позиции кнопки: tag
`Class_` → converter → type 3 → lookup ClassInfo → row ID → request raw class.
Carnage / Gunner — ранее установленная подпись класса в каталоге и выбранный
пользователем класс; её строка Class в свежем архиве сверена ниже.

## Свежие данные

Использованы существующие `index-release-archives.py` с явным SHA архива и
`extract-release-tables.py`. Источник — установленный
`Patch/Install/pakchunk1-Windows.pak`, полный SHA256
`365ceb7fc006633f4c2be9a38d33c2b8c8a527e4f1250f8b1579af170f16cdb6`.
Release snapshot `2b9ee9bbb180f064ae5f399cc41f063784f4f7b98dcc6b659d0707ed4d4cee08`.
Извлечены 3094 CSV без ошибок в пределах установленного decoder scope;
это не полная проверка всех ресурсов игры.

CSV классов имеет SHA256
`620725b3322e37b612107286ca60d72908cccfdb32449b6a2e135e4ad3c4c8bc`.
Он побайтно совпал с прежним Class CSV; номер записи изменился с 36 на 37.
Совпадение установлено по полному содержимому, не по старому offset / entry.

| Resource | Id | Type | DefaultGender |
| --- | --- | --- | --- |
| DarkMage | 1 | 1 | 1 |
| Reaper | 2 | 2 | 1 |
| Gunner | 3 | 3 | 1 |
| SwordMan | 4 | 4 | 1 |
| Fighter | 5 | 5 | 1 |

Свежий table snapshot относительно record index:
`table-snapshots/54728d7a6bef3dfa8ea916b45f29fd1ec972e5e1a5ec1a25688b9a654ca1f7f2/manifest.json`.
Полные пути, SHA и повторная проверка установленного EXE / архива закреплены
в `verify-release-creation-classes.py`.

## Проверка и продолжение

Проверка сверяет release / record / table manifests, содержимое CSV, полный
SHA установленных EXE и PAK, vptr / slots и converter anchors. Затем создаёт
строки для существующего native lookup из чисел свежего CSV. К 45 синтетическим
сценариям добавлено 9 сценариев текущих строк; Gunner type 3 возвращает row ID 3.
Engine cache при этом не читается: память таблицы остаётся явным fixture.

```powershell
# Из phone-exit/bots
python -X utf8 -m unittest test_vampir_release_creation_classes test_vampir_create_class_lookup
```

Итоговый профиль и provenance:
`F:/PhoneExit Resources/Vampir/code-clues/release-creation-classes/132fc42d2ec7c82b2653398cb173c8544e5a9d2532b946e6e3c5437e8c964155/manifest.json`.
SHA256 совпадает с именем каталога; внутри ссылка на native report 54 случаев.
Ghidra details текущего comparison: `run-d31213e3dae7` и `run-0917f674a7d0`.

Ghidra не всегда заполняет references для LEA RIP. Поиск теперь принимает
такую ссылку только после декодирования точных source-checked bytes инструкции.
Это не доверие подписи из псевдокода и не разрешение произвольного target.

Для encoder текущей сборки установлен raw class ID Carnage = 3. Значение
DefaultGender = 1 известно из данных, но остальные параметры внешности / JSON
и full producer ещё открыты. Нет подтверждения активного engine cache,
приоритета всех PAK-слоёв, серверного допуска или фактического создания.
Следом — producer внешности и целый reader / handler ID 104; отправка создания
пока не подключена.
