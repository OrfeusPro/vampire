# Выполнение GMC2 URL в 1.13.16

23 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [статической сверки участков](HEADLESS-GMC2-REQUEST-LAYOUT-11316.md).
Код выполняется в синтетической памяти Unicorn 2.1.4, без сети / процесса игры.
Capstone 5.0.6. Runtime profile пока не обновлён.

## Явные зависимости

URL slice `0x1444fa308` → `0x1444fa61d` вызывает build getter
`0x1445320c0` и ASCII append `0x1417619b0`. Они получены через prepare /
collect как полные exports. Getter читает globals `0x14b5628d8`,
`0x14b5628e8`, `0x14b5628f8`. Проверенный поиск их RIP LEA uses дал ровно
три инициализатора: `0x1411b3260`, `0x1411b3290`, `0x1411b32c0`.
Эти адреса также отдельно выгружены. Все owning collect завершены успешно.

Версия SDK берётся настоящим getter `0x14452ac30` из готового экспорта.
Copy tail `0x141453890` проверен по пяти байтам `e924223a07`: он переходит
к `0x1487f5ab9`. Импорт последнего подтверждён как vcruntime140.dll!memcpy.
Псевдокод initializers показывал вызов 0x1487e9110, но source-checked
инструкции всех трёх заканчиваются JMP 0x1487e914c. Fixture поставлен именно
на фактический target; инициализаторы и getter исполняются настоящим кодом.

## Результаты

`replay-gmc2-url-11316.py` использует `native-request-harness-11316.py`.
Проверяются полный SHA EXE, четыре exports и все загружаемые инструкции.
Разрешены только инструкции явно выбранных семи функций, проверенный copy
tail и явные fixtures. Другой адрес исполнения отклоняется, даже если страница
уже отображена в памяти. Лимиты: 16 функций, 8 exports, 30 000 инструкций
на вызов, отдельные bounds строк / heap / memcpy.

Выполнены 27 случаев: три base URL (без /, с / и пустой), четыре build codes
0 / 1 / 2 / 255 и два market; дополнительно пустые group / market, специальные
символы и текущая production база. Во всех случаях результат совпал с
`assemble_gmc2_config_url_ascii` без подмены build / version / append готовым ответом.

- Настоящие initializers записывают A / B / C.
- Getter выбирает A для 0 и 255, B для 1, C для 2.
- SDK version getter даёт 5.2.11.
- Завершающий / и специальные символы сохраняются так же, как в portable helper;
  автоматическое URL-encoding здесь не добавлено.
- Builder остаётся в inline buffer, его end canary сохранён во всех случаях.

Для production / code 0 / nmp получен URL:
`https://apis.netmarble.com/gc2/template-groups/netmarbles-v5/5.2.11?game=v5&country=G9&build=A&engine=unreal&market=nmp`.
Это локально собранная строка, HTTP-запрос не выполнялся.

Fixtures: manager/settings/CDO, FString literal storage / allocation, memcpy,
free и регистрация завершения. Growth target не перехватывается; переполнение
inline buffer не покрыто. Whole Refresh, HTTP headers, активные startup inputs
и авторизация этим replay не доказаны.

## Повторная проверка

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-gmc2-url-11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_gmc2_url_11316.py
```

Четыре теста проверяют результаты 27 случаев, initializers / canaries,
отклонение изменённых EXE / export и запрет входа по непроверенному адресу
в отображённой code page. Зарегистрирован `gmc2-url-native-11316` с полными
artifact dependencies и хешем portable helper. Автоматизация каждой функции
отмечена в release-update-targets.json; append явно ограничен inline capacity,
а Refresh помечен как исполненный только в пределах URL slice.

Библиотека `F:/PhoneExit Resources/Vampir/`:

| Материал | Путь / SHA256 |
| --- | --- |
| Build / append | `ghidra/request-exports/<SHA>/run-649b566d2b6e/details.json` / `a8c91092a8f3d87d80bf9e0bfa3c20b92e552c4639ef2f65ededd3bc5e57410b` |
| Три initializers | `ghidra/request-exports/<SHA>/run-d064d86b997f/details.json` / `b6cbad96713d894b02208876c5fe027e161184f0c4dc66dcc1b30b000a22976f` |
| Поиск initializers | `ghidra/request-exports/sdk-reference-candidates/ef466ebf592bca83e21311b965343aaaeb2ce51805784e51ae4dc238aa04004d/manifest.json` |
| Replay | `code-clues/gmc2-url-11316/a56244803e1affdc1a59b2c28f91d18325f5aef25646a7bfcde32655937504ef/manifest.json` |

Exports Refresh и version с SHA перечислены в предыдущих доказательствах.
Следующий этап — текущий header slice: проверить вызываемые getters и native
HTTP capture outputs, затем platform и сборку полного SDK profile.
