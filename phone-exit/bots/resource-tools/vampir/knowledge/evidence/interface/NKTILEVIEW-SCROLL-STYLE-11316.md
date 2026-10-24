# NkTileView: условное заполнение оформления прокрутки

25 октября 2026. EXE SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [передачи параметров](NKTILEVIEW-PARAMETER-FLOW-11316.md).
Запрос `53c4f8f6684da59865c05f88409a56e6ef9f209e96e87a3dca1985eb46440b15`
задаёт 144a8b800 и 141757d50 — точные calls из ранее изученных методов.
Оба экспортированы Ghidra в
`ghidra/request-exports/d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960/run-2518dbc2add4/`.
Псевдокод проверялся по целым инструкциям; типы Ghidra не становятся схемой свойств.

144a8b800 не дал записи значений в owner +0x430 / +0x440 / +0x450.
Он подготавливает другие параметры, используемые последующей передачей
в объект отображения. 141757d50 через вспомогательные calls передаёт управление
141757dc0; producer / reflection metadata для трёх блоков этим не установлен.
Нативный replay ниже исполняет только 144a8b800, не 141757d50 и не его callees.

## Подтверждённые условия и записи

Если qword owner +0x2d8 и qword +0x388 оба ненулевые, функция возвращается,
не изменяя объект и не вызывая проверку окружения. Ненулевой указатель не
является отдельным доказательством валидного / загруженного ресурса.

Если хотя бы один равен нулю, вызывается gate 14148ee40:

- При ненулевом результате последовательно запрашиваются точные UTF16 ключи
  `_Common/TEX_Scroll_Horizontal` и `_Common/TEX_Scroll_Vertical`.
  Они передаются resolver 1445cf4f0; результат через calls 144277e40 /
  1417e8fe0 передаётся setter 14191ab70 для блоков owner +0x2a0 и +0x350.
  Сами resolver / loader / setter в replay являются fixtures.
- В этой ветви native MOVUPS записывает четыре float32 `(1, 1, 1, 1)` в
  +0x2a8 и +0x358. По одному младшему байту в +0x2b8 / +0x368 задаётся ноль.
  Остальные три байта копируются из stack state; они не объявляются
  доказанным полным нулём enum / flags. Пространство цвета / sRGB / LinearColor,
  родительская прозрачность и Brush binding здесь не восстановлены.
- При нулевом результате gate вызывается другая цепочка с 1417f4140 и
  141409d30. В replay это явные fixtures, отложенный callback не выполняется.
  Назначение gate и runtime порядок отложенной работы ещё неизвестны.

В обеих ветвях заполнения native записывает float32 пары `(9, 8)` в
+0x2c0 / +0x2c4 и `(8, 9)` в +0x370 / +0x374. Это сырые значения параметров,
не физические пиксели и не доказанный размер текстуры / viewport. Если один
указатель задан, а другой отсутствует, ветвь заполнения затрагивает оба блока;
неверно подставлять параметры только для отсутствующей стороны по догадке.

## Ресурсы-кандидаты

В `archive-image-latest.json` найдены уникальные suffix-кандидаты:

|Ключ|Путь|PNG размер|Полный SHA256 PNG|
|---|---|---|---|
|Horizontal|/Game/RED/UI/Resource/Texture/_Common/TEX_Scroll_Horizontal|60 × 12|79f3840a8e2a2ce1f739622d67c18477ebff7146d67d3589370b4bc451a4b232|
|Vertical|/Game/RED/UI/Resource/Texture/_Common/TEX_Scroll_Vertical|12 × 60|90ca96642c09db6508d1018d76385f24c422816cefb9744a0d769eb1c35815d2|

CLI сверяет SHA каталога / PNG и containment пути, сохраняет исходные entries
и статус `suffix_candidate_not_native_resolver_proof`. Это исторический каталог
с правилами выбора largest_s_suffix; активный mounted вариант не подтверждён.
Resolver не разобран: совпадение суффикса не доказывает полный путь загрузки.
Из отношений PNG 60×12 и параметров 9×8 не выводится DPI, UV или nine-slice.

## Bounded native проверка

`replay-nktileview-scroll-style.py` исполняет целую функцию 144a8b800.
Gate, resolver, class lookup, loader, setter, free и scheduling заменены явными
fixtures. Setter только регистрирует аргументы: он не изменяет resource pointer
и не эмулирует успешную загрузку. Не исполняются scheduled callback, engine
allocation, процесс игры, отрисовка и серверная работа.

32 комбинации: наличие двух исходных указателей, gate 0 / 1, фиктивная загрузка
с нулём / ненулевым результатом, stack poison 0x11 / 0xa5. Проверены полный
возврат / стек, все байты owner, точные ключи / порядок вызовов, четыре float32
единицы, пары 9 / 8 и младшие байты флагов. Две stack poison конфигурации
подтверждают, что старшие байты флага не следует считать полным нулём.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_ui_tile_refresh.py -v
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-nktileview-scroll-style.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/53c4f8f6684da59865c05f88409a56e6ef9f209e96e87a3dca1985eb46440b15/manifest.json' --output 'F:/PhoneExit Resources/Vampir/code-clues/nktileview-scroll-style-d00a-next.json'
```

Три зарегистрированных offline теста проверяют 24 wrapper, 128 packing и
32 новых style случаев с разными границами покрытия. Отчёт новых случаев:
`code-clues/nktileview-scroll-style-d00a-02.json` вне Git. PNG-кандидаты сверяются
CLI отдельно; native check не доказывает их актуальность или отображение.
Прежний пробный отчёт сохранён. Версии Capstone / Unicorn и EXE проверяются.

Далее: полное правило resolver, ресурсный setter / Brush layout, named metadata
и условия gate. Значения не вводятся в frontend как глобальная тема или
безусловный default; генерация и применение остаются после аудита.
