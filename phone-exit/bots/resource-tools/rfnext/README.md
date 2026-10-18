# Исследование PAK RF Online Next

Данные хранятся в `F:/PhoneExit Resources/RF Online Next`. Переменная
`PHONEEXIT_RF_RESOURCES` позволяет указать другую библиотеку. Скрипты не входят
в пакет бота. Исходные игры открываются только для чтения.

Обычно повторное сканирование не нужно: поиск по asset_path, source, format,
width/height в archive-image-latest.json или галерее сразу даёт PNG и смещение
ресурса в PAK. Полный архив вариантов — archive-image-catalog.json. Карта —
maps/novus-world.png, её геометрия и источники — maps/novus-world.json.
Сырые записи и их принадлежность архивам — pak-extracted/*/entries.json.

Команды из корня проекта:

```powershell
python phone-exit/bots/resource-tools/rfnext/scan-all-paks.py
python phone-exit/bots/resource-tools/rfnext/export-textures.py
python phone-exit/bots/resource-tools/rfnext/assemble-novus.py
python phone-exit/bots/resource-tools/rfnext/build-gallery.py
```

Для просмотра постоянной библиотеки можно открыть index.html браузером либо:

```powershell
python -m http.server 17943 --bind 127.0.0.1 --directory "F:/PhoneExit Resources/RF Online Next"
```

Сканер использует pc-pak-inventory.json с точными путями установки. Уже имеющиеся
 entries.json повторно не сканируются: при обновлении самой игры нужно сравнить
отпечатки PAK и повторно исследовать изменившиеся архивы в отдельной библиотеке,
чтобы сохранить прежние результаты. Декодер загружается только из
 tools/oodle-data-shared.dll; источник, версия и SHA256 архива записаны в
 tools/oodle-source.json. Он не публикуется и не включается в продукт.

Для Novus выбирается только обзорный слой RegionMapTileTex с размером 4096×4096;
одноимённые подробные 512×512 плитки относятся к другому слою. Все прозрачные
поля, порядок осей и обрезка фиксируются в метаданных. Карта пока не имеет
проверенного преобразования координат игры в пиксели.

Редактор ПК теперь имеет каталог наблюдаемых локаций Novus. Происхождение
каждой точки, система координат, хеши, ограничения и проверка после обновления
описаны в [MAP-PROVENANCE.md](MAP-PROVENANCE.md). Источники ручных отметок:
map-labels.json; генерация каталога: build-map-catalog.py; регистрация рельефа:
register-map.py. Это координаты изображения; навигация в игре ещё не проверена.
