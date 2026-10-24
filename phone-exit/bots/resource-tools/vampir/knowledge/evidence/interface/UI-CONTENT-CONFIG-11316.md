# Чтение ContentSubName: начальная ветвь конфигурационного reader

25 октября 2026. Продолжение [источника префикса](UI-RESOURCE-PREFIX-11316.md).
Источник EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Запрос `36d9df7280a490b57e6ff96c962b89123f7835cbbfeec009a8f74e6f2f1e0399`
содержит только явный root 1445c2c30. Collector завершился с state=collected,
пустой очередью и одним новым export; повторного полного экспорта нет.

## Источники и границы

Ghidra: `ghidra/request-exports/<полный SHA EXE>/run-40f646b1556a/details.json`,
SHA256 `7e531a5bd23c58ae8711644f28467b7ff0701183f1b3718da4b8703760cfc869`.
Полная unwind функция 1445c2c30…1445c2e72 сохранена в отчёте с инструкциями;
SHA256 fragment `dd2cfb2e6a15f2c70939e2a0eef893e901a5294873784672e9c4076685e7916a`.
Псевдокод сверён с инструкциями начальной ветви. Весь reader не исполнялся.

`replay-ui-content-config.py` исполняет исходные инструкции только до
1445c2cb4, перед подготовкой callback. Unicorn 2.1.4 / Capstone 5.0.6;
полный SHA EXE и unwind root проверяются до чтения адресов. Входной stack
имеет Windows x64 alignment. Virtual lookup и строковое присваивание — fixtures.
Игра не запускается, реальные конфиги / профили не изменяются.

## Что проверено

- Начальный участок не использует первый входной RCX: объект lookup выбирается
  через dword 14b564640 и pointer 14b564638. В replay global presence всегда
  ненулевой; отсутствие глобального объекта не моделируется.
- Перед lookup временная строка обнулена. В 1445c2c91 вызов идёт через
  vtable +0x58: RCX — глобальный объект, RDX — section, R8 — key,
  R9 — временная строка; пятый аргумент — адрес объекта 14b2e5678.
  Содержимое этого filename object и precedence не подтверждены.
- Нулевой AL результата lookup обходит 14142a250. Ненулевой AL вызывает
  helper с destination из входного RDX, data pointer временной строки и
  числом UTF16 units: length−1, либо 0 при нулевой length.
- Проверены 26 случаев: lookup missing / present; пустое значение, RED,
  Other, кириллица, A/B и строка с surrogate pair; два разных первых RCX.
  Отдельно present с нулевыми pointer / length / capacity. Lookup вызывается
  один раз; helper — только при present. Пустая строка с terminator и FString
  с length 0 различаются как fixtures, в обоих случаях count=0.
- Fixture присваивания только записывает аргументы и не выделяет память;
  destination остаётся контрольным. Это проверка ветвления и ABI, а не
  подтверждение результата native копирования строки.

Отчёт вне Git: `code-clues/ui-content-config-d00a-02.json`, SHA256
`ba93259706978278251f798c5c065c8bfb48a1c26965f2b364234263f7bbf7da`.
Прежний пробный отчёт 01 сохранён отдельно; актуальная проверка относится к 02.
Пять зарегистрированных tests tile refresh прошли, включая новый reader prefix.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-ui-content-config.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/36d9df7280a490b57e6ff96c962b89123f7835cbbfeec009a8f74e6f2f1e0399/manifest.json' --output 'F:/PhoneExit Resources/Vampir/code-clues/ui-content-config-d00a-next.json'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_ui_tile_refresh.py -v
```

## Что остаётся открытым

Полная функция далее готовит callback объекты и вызывает 1445c1f50; этот путь,
cleanup и возврат не входят в replay. Поэтому обход присваивания в prefix
не доказывает сохранение destination после всех последующих callbacks.
Следующий отдельный запрос — 1445c1f50 и адреса callback из инструкций
1445c78d0 / 1445c7970: подтвердить границы и фактическую роль до исполнения.
Также остаются global config initialization / precedence и native строковые
helpers. Active settings, успешная загрузка ресурса и Brush binding не доказаны.
Внешний вид по этим результатам не генерируется.
