# Префикс UI-ресурсов: /Game и ContentSubName

25 октября 2026. Статический offline разбор EXE SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [resolver и setter](UI-RESOURCE-SETTER-11316.md).
Игра / native-код не исполнялись; профили и конфигурация не изменялись.

Узкий поиск RIP LEA ссылок на 14b5646b0 дал множество потребителей.
Выбраны только короткий initial root 1411b8860 и root 1445c6820 с двумя
ссылками на глобальный объект. Запрос
`10bcd0b5513f928e80404f7589c56fe065b3718ce75eaf8e0c5c899722e91511`
остановлен Ghidra на import tail merge стартового root; его частичный export
не объявляется завершённым. Повтора неизменённого неудачного запроса нет.

Затем запрос `bc90d71da83f31238ff22b78dedffb101c9bbc8f4269e4f30258762b67b8b9fb`
изолировал 1445c6820 и три точных строковых callee: 141426b30, 1414277b0,
141429e10. Последний уже имел готовый export; остальные три выгружены в
`ghidra/request-exports/d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960/run-d8dc7f6c51b7/`.
Инспектор сохраняет семь полных unwind-фрагментов четырёх roots; повторного
массового экспорта нет. Helpers не исполнялись и не выдаются за готовую
переносимую строковую реализацию.

## Подтверждённый статический путь

1445c6820 подаёт в 1445c2c30 указатель `*RCX`, адрес глобального значения
14b564680, точные UTF16 строки NnCoreSetting и ContentSubName. Их literal
addresses — 149558590 и 149558570. Config reader 1445c2c30 ещё не исследован
целиком: источники конфигурации, precedence и ошибки чтения остаются неизвестными.

Далее 1445c6b3a / 1445c6b47 / 1445c6b4e передают `/Game` из 14920e750
и адрес глобального префикса 14b5646b0 в 1414277b0. Псевдокод строкового
callee и инструкции согласованы с назначением строки; фактический runtime
результат после всей загрузки не прочитан.

После этого:

1. Сравнивается dword 14b564688 с 1. При значении <=1 ветвь добавления пропускается.
2. Иначе в 14142b760 передаются временная строка, точный разделитель `/`
   из 1489f1520 и объект 14b564680.
3. Результат передаётся в 141429e10 с адресом глобального префикса и длиной
   без завершающего символа. Затем временное значение освобождается.

Это источник условного сегмента префикса. В предыдущем resolver короткий
ключ использует `/UI/Resource/Texture/%s`, затем глобальный префикс.
Полную цепочку строковых helper calls ещё нужно выполнить / проверить перед
автоматическим построением пути; строка `/Game/RED/...` пока условный вывод,
а не прочитанное активное значение. Случаи пустого / нестандартного сегмента
не нормализуются самодельным join.

## Снимок конфигурации

Проверен существующий snapshot
`resource-config-snapshots/12abc7a1cda6b050250662acab29155092484da595d50c0e93c2ffff42bfb145/manifest.json`.
Manifest привязан к тому же EXE SHA. В DefaultGame.ini ровно одна запись
в точной секции NnCoreSetting: строка 27, ContentSubName=RED.
Инспектор сохраняет полный SHA manifest и plaintext snapshot отдельно.
`payload_sha256` manifest относится к stored ciphertext, его нельзя подменять
SHA текстового файла или сравнивать с ним как одинаковый объект.

Manifest прямо оставляет `config_precedence_verified=false` и
`active_runtime_settings_verified=false`. Значение RED подтверждено только
для этого снимка, не для активного GConfig или mounted набора клиента.
Config files не выводятся целиком, не копируются в Git и не изменяются.

## Проверка и применение

`inspect-ui-resource-prefix.py` проверяет source SHA, explicit roots / unwind,
полное декодирование, конкретные calls / branch / literals и source-bound
конфигурационный manifest. Парсер читает только единственную точную запись
ContentSubName в NnCoreSetting; DEFAULT и одноимённая другая секция не наследуются.
Дубликаты отклоняются, пустое значение сохраняется пустым. Это offline анализ,
не замена нативного config reader.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-ui-resource-prefix.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/bc90d71da83f31238ff22b78dedffb101c9bbc8f4269e4f30258762b67b8b9fb/manifest.json' --config-manifest 'F:/PhoneExit Resources/Vampir/resource-config-snapshots/12abc7a1cda6b050250662acab29155092484da595d50c0e93c2ffff42bfb145/manifest.json' --output 'F:/PhoneExit Resources/Vampir/code-clues/ui-resource-prefix-d00a-next.json'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_ui_property_coverage.py -v
```

Отчёт `code-clues/ui-resource-prefix-d00a-01.json` вне Git. 14 tests аудита
прошли, включая exact section / duplicate / blank / отсутствие DEFAULT inheritance.
Это не native replay нового config пути; прежний registered check покрывает
только ранее установленные Refresh / packing / style / setter области.
Далее — native config reader / string helpers и проверка active resources,
после этого разрешённое применение в генераторе. Общая фаза аудита не закрыта.
