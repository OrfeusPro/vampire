# Владелец обновления и аварийное восстановление v4

`update --auto`, явные `--baseline` и `--resume` подключены к новому
управляемому owner через машинный selector. Guardian удерживает OS lease и
общий `research.lock`, а рабочий процесс получает задание только после
присоединения к Windows Job Object и записи точного manifest. Исходники
59 прежних frozen native / research inputs сохранены.
[Отчёты, компоненты и полные SHA](AUTO-UPDATE-OWNER-RECOVERY-V4-11322.json).

## Что изменилось

Прежний PID-only lock мог пережить падение процесса и блокировать следующий
проход. Новый JSON lock содержит recipe, epoch, producer SHA, канонический root,
идентичности guardian / worker и имя группы. PID сверяется вместе с creation time
и Windows session. Первичная запись выполняется create-if-absent из полностью
записанного временного файла; чужой lock не заменяется. Windows READ handle
блокирует изменение / удаление активного primary, сохраняя чтение worker.

Worker стартует с `-S` и ждёт stdin до остальных импортов. Guardian назначает
его группе с kill-on-close, ненаследуемым handle и запретом breakaway, затем
передаёт payload. Только после проверки lock и членства запускаются site hooks
и обычный обновлятор. Потомки обычных subprocess принадлежат той же группе.
При завершении / исключении guardian закрывает группу и проверяет отсутствие
активных процессов, ждёт worker и поток журнала перед освобождением lock.

Следующий явный запуск восстанавливает только manifest того же producer guard
и Windows session. Проверяются immutable owner snapshot, полные bytes / SHA,
file identity, aliases и отсутствие точных старых процессов / живой группы.
Проверенный DELETE handle удаляет именно открытый объект. Прежний lock и
двухфазные квитанции сохраняются по epoch и fingerprint наблюдений. Обрыв после
prepared receipt допускает новое наблюдение без перезаписи прежней попытки.
Возраст файла и неизвестный результат probe не разрешают очистку.

Автоматический выбор журнала и его callback выполняются внутри managed worker.
Callback связывает durable `run.json` с `progress.json` владельца. Изменение
scaffolding создаёт новую identity общего прохода, но эти три модуля не добавляются
эвристическим обходом в зависимости каждого native / resource stage. Полные
SHA зависимостей самих stages и admission остаются обязательными.

Наблюдатель при следующем явном старте подхватывает прежний живой worker либо
читает его конечный result. Потеря подхваченного worker без result разрешает
один повтор после quiet period. Stop сохраняет interrupted retry. Общий
`settle_child` записывает результат до сброса child identity как в обычном цикле,
так и после drain при исключении; готовый result больше не теряется.

## Проверки и область результата

Прошли 1422 tooling теста за 147,392 секунды, включая 96 новых: Windows backend —
34, lease — 35, dispatcher / routing — 27. Три прежних symlink cases пропущены
из-за прав Windows; новые тесты исполнены полностью. Шесть дополнительных
штатных checks прошли; три с неизменными входами использованы из прежнего кэша.
Source-bound native suites клиента и JVM не запускались.

Настоящие Windows-проверки использовали только временные процессы: worker,
grandchild, вспомогательные conhost и отдельную копию dispatcher со stub consumer.
В одном сценарии guardian аварийно завершён; группа закрылась, lock восстановлен
следующим явным запуском, содержимое durable fixture stage сохранилось и счётчик
его выполнения остался равен 1. Отдельно проверено, что sitecustomize выполняется
после assign, а callback сохраняет точную связь с fixture journal.

Негативные случаи включают PID reuse, access denied / unknown probes, живого
потомка, foreign / legacy lock, смену producer SHA / session, повреждённый JSON,
duplicate keys, превышение бюджета, подмену file identity / alias и replacement
между закрытием READ и открытием DELETE handle. Чужой replacement сохраняется.
Прерывание при передаче, отказ assign, ошибка выходного потока и отсутствие
result не объявляются успешным обновлением.

Реальная установка, игровые команды и полный production update этим пакетом
не запускались. Указанный SHA 1.13.22 связывает исследовательский пакет;
совместимость клиента и работа онлайн не подтверждаются инфраструктурными тестами.

## Оставшиеся границы

Прежние PID-only `research.lock` и `ghidra.lock` остаются конкретными блокерами:
история их потомков не доказана. При другом producer guard или Windows session
managed lock требует отдельной диагностики. POSIX lease — fixture-ветка для
cooperating writers; рабочий Job backend требует Windows.

Наблюдатель остаётся выключенным по запросу пользователя. Новый пакет не включает
автозапуск Windows и не запускает обновление при обычном «продолжай».
Ручной ярлык запускает один явный проход. Далее — production-проверка по явному
разрешению, общий адаптер context projections и уменьшение повторных затрат
на execution inputs / archive SHA при сохранении финальных барьеров.
[Команды и диагностика](../../RESUMABLE-UPDATE.md).

Семантика наследования группы и kill-on-close сверена с
[Microsoft Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects),
порядок `-S` / `site.main()` — с
[Python 3.14 site](https://docs.python.org/3.14/library/site.html).
