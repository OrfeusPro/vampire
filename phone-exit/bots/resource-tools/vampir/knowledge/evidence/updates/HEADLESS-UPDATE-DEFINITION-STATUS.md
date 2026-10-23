# Актуальность определений сохранённого update

Команда [update-status](../../RESUMABLE-UPDATE.md) теперь возвращает `definitions`:

- `current: true` — SHA реестров контрактов, checks и target plans совпадают
  с сохранённым планом;
- `current: false` и `changed` — определения изменились, требуется `--resume`;
- `current: null` — старый журнал без SHA определений; актуальность не установлена.

Новые прогоны сохраняют `plan.definition_sha256`. Status читает только маленькие
локальные определения. Он не запускает проверки, Ghidra, replay или авторизацию,
не меняет журнал и не проверяет установленный клиент. Даже совпадение определений
не подтверждает свежесть всех ресурсов, tools и outputs: их проверяет продолжение.
Исторический отчёт без этого поля не переписывается автоматически.

Проверены неизменные / изменённые / отсутствующие определения, старый журнал,
отсутствие изменения входного run, а также прежний сценарий reuse / read-only status.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_update_definition_status.py
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_update_run.py -k test_resume_reuses_completed_stages_and_status_is_read_only
```

Отдельный контроль нового `native-version-platform-context` после `finish`
использовал сохранённый check result за 0,052 секунды, с запрещённым в эксперименте
запуском subprocess. Это время одного cached check, не всей цепочки обновления.
Машинный отчёт:
`F:/PhoneExit Resources/Vampir/knowledge/offline-cache-acceptance/249696e3617862c95832dc1732daf6f8742eb658ab618b1c9c0e004f870134fb/manifest.json`.
SHA отчёта совпадает с именем каталога. Полный новый замер переноса игры ещё нужен.
