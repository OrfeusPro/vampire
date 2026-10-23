# Текущие обработчики результата NID: статическая сверка 1.13.16

23 октября 2026. EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [URL / query](HEADLESS-NID-QUERY-11316.md).
Только сохранённые файлы: нет процесса игры, сети, входа или чтения аккаунтов.

## Поиск и текущие экспорты

Новый план `knowledge/release-nid-result-targets.json` закрепляет полные точные
ASCII diagnostics исторических OnDeepLink / OnResult из source-bound evidence
SHA `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Locator повторно проверил baseline literals / roots, затем нашёл текущие
кандидаты. Явный prepare / collect получил только два текущих roots:

| Роль по diagnostic signature | Текущий адрес | Exported instructions |
| --- | --- | --- |
| FNetmarbleIDContent::OnDeepLink(const FString &) | 0x1450f2c80 | 343 |
| FNetmarbleIDContent::OnResult(const FString &) | 0x1450f3e40 | 1041 |

Оба exports имеют completed decompilation / block coverage. Audit проверяет
полный SHA EXE / export и исходные байты всех 1384 экспортированных инструкций.
Эта проверка не гарантирует отсутствия пропущенных instructions вне списка;
прежняя особенность cleanup tails в другом root остаётся отдельным unknown.

## Подтверждённые связи

CALL `0x1450f30bb` из OnDeepLink направлен на `0x1450f3e40`.
В OnResult по `0x1450f43a1` есть точная инструкция
`TEST dword ptr [R15 + 0x150],0xfffffffa`. Она соответствует маске режима;
полное поведение caller и исходы веток этим не исполнены.

Семь descriptor globals связаны с настоящими UTF-16 literals через семь
маленьких initializer roots: LEA RDX literal → LEA RCX global → CALL FString
constructor `0x141426b30`. Каждый initializer содержит семь инструкций.
Поиск ограничен максимум 16 маленькими самостоятельными unwind roots до
64 байт; decode не расширяет их на chained fragments / дерево вызовов.

| Global | Точный ключ |
| --- | --- |
| 0x14b5d5878 | result |
| 0x14b5d5918 | resultCode |
| 0x14b5d5928 | accessToken |
| 0x14b5d5938 | refreshToken |
| 0x14b5d58d8 | channelKey |
| 0x14b5d5948 | netmarbleId |
| 0x14b5d5958 | joinedCountryCode |

Для каждого global подтверждено использование в экспортированных handlers.
Это не чтение реальных токенов: runtime FString descriptors не загружаются,
проверяются только инструкции и литералы сохранённого EXE.

## Оставшиеся проверки и автоматизация

Это static audit, не native replay обработки результата. Missing / empty
fields, integer parser / channel mapper, error branches, token setters,
persistence и callback delivery ещё нужно сверить на текущей сборке.
Старые 22 fixture outcomes из [исторического OnResult](HEADLESS-NID-VALIDATION.md)
не перенесены автоматически. Runtime profile остаётся выключенным.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/audit-nid-result-11316.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_nid_result_source_11316.py
python -X utf8 phone-exit/bots/resource-tools/vampir/locate-release-update-targets.py --targets phone-exit/bots/resource-tools/vampir/knowledge/release-nid-result-targets.json --source-sha256 d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960
```

Три теста проверяют текущие bindings / route / mask и отказ при подмене ключа
или повреждении export. Check `nid-result-source-11316` связан с текущим SHA,
export и tools. План добавлен в additional_target_plans общего updater:
после смены EXE можно автоматически найти кандидаты по точным diagnostics,
но проверка остаётся source-bound и требует переноса на новый SHA.
Ни найденный candidate, ни совпадение имени не включают runtime автоматически.

Материалы в `F:/PhoneExit Resources/Vampir/`:

- Locator: `code-clues/update-targets/155a7f0bdfc173f351a82f6e9323dff4d0ceae48016882a62254f20c1c98eb55/manifest.json`.
- Export: `ghidra/request-exports/<SHA>/run-2493cfa0c5bc/details.json`,
  SHA `a530c6c39e49e29fea6593b3c0d0d12cf1628c441f7601a00b02240679450d5a`.
- Audit: `code-clues/nid-result-source-11316/704acc6ca032a99fcfb5f4fb7cc8546e2b24ed17ab5fc0ee865cd02e38cf74f7/manifest.json`.

Далее перенести ограниченный OnResult replay на готовый текущий export,
сверить missing / empty поля и раздельные adoption arguments. Затем auth source
guards / явное подключение профиля и живая проверка после доступности серверов.
