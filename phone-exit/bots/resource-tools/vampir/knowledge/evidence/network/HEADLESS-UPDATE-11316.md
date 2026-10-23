# Обновление клиента до 1.13.16

23 октября 2026 пользователь подтвердил завершение загрузки: сначала около
500 МБ в лаунчере, затем игра запросила ещё 19,2 МБ. После этого выполнен
штатный `knowledge-index.py update` с последним полным baseline.

## Источники

- Прежний EXE SHA256:
  `98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
- Новый EXE SHA256:
  `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
- Сохранён отдельный immutable EXE в `client-code-snapshots/<новый SHA>/`.
- Новый DefaultGame.ini: AppVersion `1.13.16`, ConfigPrefix `real`,
  CdnConfig true. SHA256 файла:
  `f5f0f4b3d4e0a41f93fc1de2cfe8f4bb0789ea44e7df0b99598162cf6653585a`.
- Установленный `Patch/windows.manifestlist` разобран существующим parser:
  patch revision `262487`, ранее `261105`.

Библиотека материалов: `F:/PhoneExit Resources/Vampir/`.
Все пути ниже относительно неё; большие материалы вне Git.

| Материал | Путь |
| --- | --- |
| Полный baseline | `knowledge/update-audits/e9c3dd6f62bd6e051610d0e70cdba6d31e5c3cad6306ad5b55fd025c50357aec/manifest.json` |
| Новый audit | `knowledge/update-audits/c44b60d512a5b6a07a3ca7f6242eb23a385d36c87c67a7490fb2bad3c150b4db/manifest.json` |
| Итог update | `knowledge/update-results/10aafe843e8672c07f9f8e1984eebd515baa1bd04f8c62204979c0bc44daecbc/manifest.json` |
| Конфигурация | `resource-config-snapshots/12abc7a1cda6b050250662acab29155092484da595d50c0e93c2ffff42bfb145/manifest.json` |

Вызов из корня репозитория:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/knowledge-index.py update --baseline 'F:/PhoneExit Resources/Vampir/knowledge/update-audits/e9c3dd6f62bd6e051610d0e70cdba6d31e5c3cad6306ad5b55fd025c50357aec/manifest.json'
```

## Полное сравнение и доступные данные

Полные SHA посчитаны для 165 архивов. Inventory, размеры и mtime стабильны
до / после чтения и сохранения снимка. Изменились два архива; остальные 163
совпали по полному SHA с baseline.

| Архив | Новый SHA256 |
| --- | --- |
| `Content/Paks/ProjectRED-Windows.pak` | `9803fa475ae3cb501519b341a5fc49dafd8540c8351def2cf6cb97ff0cf1685d` |
| `Patch/Install/pakchunk1-Windows.pak` | `15cf4f880170e87fc5fdea661cf9ba3d54a4f66c607844f5ab1047ed87f1e6a4` |

Семь resource steps: шесть passed, один failed. Основной архив: scanner разобрал
12 576 records, пропустил 76 encrypted и 52 по размеру. Сравнение старых blobs
нашло 3 210 точных совпадений из 3 325 сохранённых; 115 не наблюдались.
Извлечены 249 таблиц, errors 0; 41 имеет точное совпадение содержимого,
208 без такого совпадения. Это не доказывает идентичность строк по старым ID.

`pakchunk1`: разобраны 3 098 records, 9 пропущены по размеру. Старых сохранённых
blobs для этого архива не было. `extract-release-tables.py` отклонил общий старый
`table-study/index.json`: он относится к другому архиву. Это конкретная нехватка
подходящего baseline, не доказательство отсутствия таблиц или ошибки декодирования.
Не повторять тот же вызов с тем же неподходящим индексом.

Итоговая очередь содержит 17 пунктов: 14 вопросов из-за смены EXE, две проверки
связей ресурсов и один отказ сравнения таблиц `pakchunk1`. Новый baseline
автоматически не продвинут; compatibility остаётся `not_established`.

## Границы и следующий шаг

Старые exports, адреса, replay и runtime profile остаются привязанными к SHA
`98802d550890…`; совместимость нового EXE не объявлена. Смена версии может быть
связана с прежним `10036`, но причинная связь ещё не проверена. Живой вход бота
после обновления не выполнялся, авторизация и игровые команды в update отсутствуют.

Далее найти в новой сборке кандидатов SDK / GMC2 и выбора EU-лобби, подготовить
явные задания для нового SHA и сверить контракт. Затем проверить свежий профиль
входа и список персонажей. Для `pakchunk1` требуется собственный индекс таблиц
либо отдельное извлечение без предположения о соответствии старому архиву.
