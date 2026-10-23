# Экспорт явных функций без прежнего comparison project

23 октября 2026. Продолжение [поиска ориентиров обновления](../../UPDATE-TARGETS.md).
Новый EXE SHA256:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.

## Подготовка и результат

`prepare` ранее нашёл два launcher candidates; `collect` остановился из-за
отсутствия comparison project. Теперь при его отсутствии используется отдельный
source-specific проект: `ghidra/request-projects/<SHA>/RequestedRelease.gpr`.
Import и последующий process запускаются с `-noanalysis`, CPU 2, heap 4 ГБ.
Дизассемблируются и экспортируются только явные unwind roots из задания, до 32.
Старые comparison projects, профили, роли и указатели не изменяются.

Общий индекс принимает `ghidra/request-exports/<SHA>/run-*/details.json` с receipt,
проверяет SHA источника, инструкции и связанные pseudocode files. Готовый экспорт
используется повторно: повтор `collect` завершился reused без JVM и новых файлов
экспорта. Незавершённый import сохраняется с логами, повторный import не запускается
скрытно. При нескольких comparison projects прежняя неоднозначность остаётся очередью.

Библиотека: `F:/PhoneExit Resources/Vampir/`. Итоговый экспорт:
`ghidra/request-exports/d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960/run-e6508b986175/details.json`.
SHA256 отчёта:
`c9923787de462d4bdca9e03cdcf59a9ff333003cae0b574e9ee43c74fb71e101`.

| Явная функция | Инструкции | Байты тела / инструкций | Decompiler |
| --- | --- | --- | --- |
| `0x1444ee9d0` | 652 | 2 567 / 2 567 | completed |
| `0x144503b10` | 679 | 2 694 / 2 694 | completed |

В C сохранены комментарии о пересечении globals; пустой message не означает
отсутствие всех предупреждений. Ключи, callbacks и runtime SDK ещё не перенесены.

## Неполные попытки сохранены

Первый import создал существующие function placeholders с body_bytes 1.
Декомпилятор выдал C, но listing до декомпиляции содержал только первую инструкцию.
Это обнаружено по фактическому JSON до использования результата как контракта.
Первый run `run-bafb46c14caf` сохранён; индекс теперь отмечает его incomplete,
так как instruction coverage превышает заявленное тело. Он не заменяет полный export.

Перед экспортом добавлены явный disassemble и `CreateFunctionCmd.fixupFunctionBody`.
Сигнатура API проверена локальным `javap` закреплённой Ghidra 12.1.4. Второй
run `run-2420fa57b436` получил полные тела, но runner отклонил receipt: Ghidra
пишет другую строку сохранения для processed file. Логи и материалы сохранены.
Проверка теперь принимает две точные формы Save succeeded. Последний run завершён,
receipt проверен общим importer; owning JVM и collect process терминальны.

## Проверки и пределы

Шесть тестов requested collector покрывают import / reuse, отсутствие лишних
функций, запрет non-root адреса, повреждённый source, незавершённый проект и
однобайтный placeholder. Реальный export отдельно сверяется с полными SHA двух EXE
и всеми инструкциями нового листинга. Ещё шесть тестов индекса и 12 lifecycle tests
прошли, включая сохранение полного варианта при появлении неполного.

При сравнении с прежними функциями `0x1444ef840` / `0x144504980` число инструкций
совпало. После маскирования RIP displacement и direct CALL/JMP immediates других
различий нет; внутренние branch offsets также сверены. Это сравнение формы кода:
адресаты внешних calls, содержимое globals и их смысл оно не подтверждает.

Игра и авторизация не запускались; память процесса не читалась. Runtime profile
остаётся на прежнем SHA. Следующий шаг — сверка новых ключей / headers / URL /
callbacks и SDK/GMC2 зависимостей, затем перенос затронутых auth checks.
